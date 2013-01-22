from tastypie import authorization as tastypie_authorization, fields as tastypie_fields

from tastypie_mongoengine import fields as tastypie_mongoengine_fields, paginator, resources

from mongo_auth import backends

from piplmesh.api import authorization, fields, models as api_models, signals, tasks

class UserResource(resources.MongoEngineResource):
    class Meta:
        queryset = backends.User.objects.all()
        fields = ('username', 'is_online')
        allowed_methods = ()

class UploadedFileResource(resources.MongoEngineResource):
    class Meta:
        queryset = api_models.UploadedFile.objects.all()
        allowed_methods = ()

class AuthoredResource(resources.MongoEngineResource):
    created_time = tastypie_fields.DateTimeField(attribute='created_time', null=False, readonly=True)
    author = tastypie_mongoengine_fields.ReferenceField(to='piplmesh.api.resources.UserResource', attribute='author', null=False, full=True, readonly=True)

    def hydrate(self, bundle):
        bundle = super(AuthoredResource, self).hydrate(bundle)
        bundle.obj.author = bundle.request.user
        return bundle

class CommentResource(AuthoredResource):
    def obj_create(self, bundle, request=None, **kwargs):
        bundle = super(CommentResource, self).obj_create(bundle, request=request, **kwargs)

        # By default, comment author is subscribed to the post
        if bundle.obj.author not in self.instance.subscribers:
            self.instance.subscribers.append(bundle.obj.author)
            self.instance.save()

        signals.comment_created.send(sender=self, comment=bundle.obj, post=self.instance, request=request or bundle.request, bundle=bundle)

        # We process notifications asynchronously as it could
        # take long and we want REST request to finish quick
        tasks.process_notifications_on_new_comment.delay(bundle.obj.pk, self.instance.pk)

        return bundle

    class Meta:
        object_class = api_models.Comment
        allowed_methods = ('get', 'post', 'put', 'patch', 'delete')
        # TODO: Make proper authorization, current implementation is for development use only
        authorization = tastypie_authorization.Authorization()
        paginator_class = paginator.Paginator

class NotificationResource(resources.MongoEngineResource):
    post = tastypie_mongoengine_fields.ReferenceField(to='piplmesh.api.resources.PostResource', attribute='post', null=False, full=False, readonly=True)
    comment = fields.CustomReferenceField(to='piplmesh.api.resources.CommentResource', getter=lambda obj: obj.post.get_comment(obj.comment), setter=lambda obj: obj.pk, null=False, full=True, readonly=True)

    @classmethod
    def api_field_options(cls, name, field, options):
        # We cannot simply call super(NotificationResource, cls).api_field_options(name, field, options)
        # because api_field_options is called in metaclass class constructor before the class has
        # been created, so NotificationResource does not yet exist
        # It is in fact probably wrong to call class methods on the class which does not really yet
        # exist, but this is how Tastypie has it, so we are mostly stuck with it
        me = next(c for c in cls.__mro__ if c.__module__ == __name__ and c.__name__ == 'NotificationResource')
        options = super(me, cls).api_field_options(name, field, options)

        # We are setting readonly flag to all fields except "read" flag, because
        # we do not want clients to change other values of notifications
        if name != 'read':
            options['readonly'] = True
        return options

    class Meta:
        queryset = api_models.Notification.objects.all()
        allowed_methods = ('get', 'patch',)
        authorization = authorization.NotificationAuthorization()
        excludes = ('recipient',)

class ImageAttachmentResource(AuthoredResource):
    image_file = tastypie_mongoengine_fields.ReferenceField(to='piplmesh.api.resources.UploadedFileResource', attribute='image_file', null=False, full=True)
    image_description = tastypie_fields.CharField(attribute='image_description', default='', null=False, blank=True)

    class Meta:
        object_class = api_models.ImageAttachment

class LinkAttachmentResource(AuthoredResource):
    link_caption = tastypie_fields.CharField(attribute='link_caption', default='', null=False, blank=True)
    link_description = tastypie_fields.CharField(attribute='link_description', default='', null=False, blank=True)

    class Meta:
        object_class = api_models.LinkAttachment

class AttachmentResource(AuthoredResource):
    class Meta:
        object_class = api_models.Attachment
        allowed_methods = ('get', 'post', 'put', 'patch', 'delete')
        # TODO: Make proper authorization, current implementation is for development use only
        authorization = tastypie_authorization.Authorization()

        polymorphic = {
            'image': ImageAttachmentResource,
            'link': LinkAttachmentResource,
        }

class RunResource(AuthoredResource):
    class Meta:
        object_class = api_models.Run
        allowed_methods = ('get', 'post', 'delete')
        # TODO: Make proper authorization, current implementation is for development use only
        authorization = tastypie_authorization.Authorization()

    def obj_create(self, bundle, request=None, **kwargs):
        bundle = super(RunResource, self).obj_create(bundle, request=request, **kwargs)

        # By default, run author is subscribed to the post
        if bundle.obj.author not in self.instance.subscribers:
            self.instance.subscribers.append(bundle.obj.author)
            self.instance.save()

        for run in self.instance.runs:
            if bundle.obj.author == run.author:
                if bundle.obj != run:
                    self.instance.runs.remove(run)
                    self.instance.save()

        for hug in self.instance.hugs:
            if bundle.obj.author == hug.author:
                self.instance.hugs.remove(hug)
                self.instance.save()

        return bundle


class HugResource(AuthoredResource):
    class Meta:
        object_class = api_models.Hug
        allowed_methods = ('get', 'post', 'delete')
        # TODO: Make proper authorization, current implementation is for development use only
        authorization = tastypie_authorization.Authorization()

    def obj_create(self, bundle, request=None, **kwargs):
        bundle = super(HugResource, self).obj_create(bundle, request=request, **kwargs)

        # By default, hug author is subscribed to the post
        if bundle.obj.author not in self.instance.subscribers:
            self.instance.subscribers.append(bundle.obj.author)
            self.instance.save()

        for hug in self.instance.hugs:
            if bundle.obj.author == hug.author:
                if bundle.obj != hug:
                    self.instance.hugs.remove(hug)
                    self.instance.save()

        for run in self.instance.runs:
            if bundle.obj.author == run.author:
                self.instance.runs.remove(run)
                self.instance.save()

        #signals.post_created.send(sender=self, post=bundle.obj, request=request or bundle.request, bundle=bundle)

        return bundle


class PostResource(AuthoredResource):
    """
    Query set is ordered by updated time for following reasons:
     * those who open web page anew will get posts in updated time order
     * others with already opened page will get updated posts again as they
       will request them based on ID of current newest post

    This is useful if we would like to show on the client side that post has been updated
    (but we do not necessary have to reorder them, this depends on the client code).
    """

    updated_time = tastypie_fields.DateTimeField(attribute='updated_time', null=False, readonly=True)
    comments = tastypie_mongoengine_fields.EmbeddedListField(of='piplmesh.api.resources.CommentResource', attribute='comments', default=lambda: [], null=True, full=False)
    attachments = tastypie_mongoengine_fields.EmbeddedListField(of='piplmesh.api.resources.AttachmentResource', attribute='attachments', default=lambda: [], null=True, full=True)
    runs = tastypie_mongoengine_fields.EmbeddedListField(of='piplmesh.api.resources.RunResource', attribute='runs', default=lambda: [], null=True, full=True)
    hugs = tastypie_mongoengine_fields.EmbeddedListField(of='piplmesh.api.resources.HugResource', attribute='hugs', default=lambda: [], null=True, full=True)

    def obj_create(self, bundle, request=None, **kwargs):
        bundle = super(PostResource, self).obj_create(bundle, request=request, **kwargs)

        # By default, post author is subscribed to the post
        bundle.obj.subscribers.append(bundle.obj.author)
        bundle.obj.save()

        signals.post_created.send(sender=self, post=bundle.obj, request=request or bundle.request, bundle=bundle)

        return bundle

    def obj_update(self, bundle, request=None, **kwargs):
        bundle = super(PostResource, self).obj_update(bundle, request=request, **kwargs)

        signals.post_updated.send(sender=self, post=bundle.obj, request=request or bundle.request, bundle=bundle)

        return bundle

    class Meta:
        queryset = api_models.Post.objects.all().order_by('-updated_time')
        allowed_methods = ('get', 'post', 'put', 'patch', 'delete')
        authorization = authorization.PostAuthorization()
        paginator_class = paginator.Paginator
