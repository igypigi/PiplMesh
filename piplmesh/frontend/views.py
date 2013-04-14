import traceback

from django import dispatch, http
from django.conf import settings
from django.contrib import messages
from django.core import exceptions, mail, urlresolvers
from django.core.files import storage
from django.test import client
from django.utils import simplejson
from django.utils.translation import ugettext_lazy as _
from django.views import generic as generic_views

from mongoengine import signals as mongoengine_signals

from tastypie import http as tastypie_http

from mongogeneric import detail

from mongo_auth import backends

from pushserver.utils import updates

from piplmesh import nodes
from piplmesh.nodes import models as nodes_models
from piplmesh.api import models as api_models, resources, signals
from piplmesh.frontend import forms, tasks

class HomeView(generic_views.TemplateView):
    template_name = 'home.html'

# TODO: Get HTML5 geolocation data and store it into request session
class OutsideView(generic_views.TemplateView):
    template_name = 'outside.html'

class SearchView(generic_views.TemplateView):
    template_name = 'search.html'

class AboutView(generic_views.TemplateView):
    template_name = 'about.html'

class PrivacyView(generic_views.TemplateView):
    template_name = 'privacy.html'

class ContactView(generic_views.FormView):
    """
    This view checks if all contact data are valid and then sends e-mail to site managers.
    
    User is redirected back to the contact page.
    """

    template_name = 'contact.html'
    success_url = urlresolvers.reverse_lazy('contact')
    form_class = forms.ContactForm

    def form_valid(self, form):
        mail.mail_managers(form.cleaned_data['subject'], form.cleaned_data['message'], form.cleaned_data['email'])
        messages.success(self.request, _("Thank you. Your message has been successfully sent."))
        return super(ContactView, self).form_valid(form)

class UserView(detail.DetailView):
    """
    This view checks if user exist in database and returns his user page (profile).
    """

    template_name = 'user.html'
    document = backends.User
    slug_field = 'username'
    slug_url_kwarg = 'username'

class LocationView(generic_views.FormView):
    form_class = forms.LocationForm

    # TODO: Redirect to initiator page
    success_url = urlresolvers.reverse_lazy('home')

    def form_valid(self, form):
        location = form.cleaned_data['location']

        if location == forms.NO_MOCKING_ID:
            nodes.flush_session(self.request)
        else:
            node_backend, node_id = nodes_models.Node.parse_full_node_id(location)
            self.request.session[nodes.SESSION_KEY] = node_id
            self.request.session[nodes.BACKEND_SESSION_KEY] = node_backend
            self.request.session[nodes.MOCKING_SESSION_KEY] = True

        return super(LocationView, self).form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, form.errors)
        return http.HttpResponseRedirect(self.get_success_url())

    def dispatch(self, request, *args, **kwargs):
        if request.user and request.user.is_authenticated() and request.user.is_staff:
            return super(LocationView, self).dispatch(request, *args, **kwargs)
        raise exceptions.PermissionDenied

def upload_view(request):
    if request.method != 'POST':
        return http.HttpResponseBadRequest()

    resource = resources.UploadedFileResource()

    # TODO: Provide some user feedback while uploading

    uploaded_files = []
    for field, files in request.FILES.iterlists():
        for file in files:
            # We let storage decide a name
            filename = storage.default_storage.save('', file)

            uploaded_file = api_models.UploadedFile()
            uploaded_file.author = request.user
            uploaded_file.filename = filename
            uploaded_file.content_type = file.content_type
            uploaded_file.save()

            uploaded_files.append({
                'filename': filename,
                'resource_uri': resource.get_resource_uri(uploaded_file)
            })

    # TODO: Create background task to process uploaded file (check content type (both in GridFS file and UploadedFile document), resize images)

    return resource.create_response(request, uploaded_files, response_class=tastypie_http.HttpAccepted)

@dispatch.receiver(signals.post_created)
@dispatch.receiver(signals.post_updated)
def send_update_on_published_post(sender, post, request, bundle, **kwargs):
    """
    Sends update through push server when a post is published.
    """

    # TODO: Send this only the first time the post is published or every time? When are other cases when "post_updated" is triggered?
    if post.is_published:
        output_bundle = sender.full_dehydrate(bundle)
        output_bundle = sender.alter_detail_data_to_serialize(request, output_bundle)

        serialized_update = sender.serialize(request, {
            'type': 'post_published',
            'post': output_bundle.data,
        }, 'application/json')

        # We send update asynchronously as it could block and we
        # want REST request to finish quick
        tasks.send_update.delay(serialized_update)

@dispatch.receiver(signals.comment_created)
def send_update_on_comment(sender, comment, post, request, bundle, **kwargs):
    """
    Sends update through push server when a comment is made.
    """

    output_bundle = sender.full_dehydrate(bundle)
    output_bundle = sender.alter_detail_data_to_serialize(request, output_bundle)

    serialized_update = sender.serialize(request, {
        'type': 'comment_made',
        'comment': output_bundle.data,
        'post_id': post.id,
    }, 'application/json')

    # We send update asynchronously as it could block and we
    # want REST request to finish quick
    tasks.send_update.delay(serialized_update)

@mongoengine_signals.post_save.connect_via(sender=api_models.Notification)
def send_update_on_new_notification(sender, document, created, **kwargs):
    """
    Sends update through push server to the user when a new notification is created.

    Important: This signal should be processed only asynchronously (background task) as
    it can block. So currently it is assumed that notification documents are created
    only in background tasks.
    """

    if not created:
        return

    notification = document

    def test_if_running_as_celery_worker():
        # Used in tests
        if getattr(settings, 'CELERY_ALWAYS_EAGER', False):
            return True

        for filename, line_number, function_name, text in traceback.extract_stack():
            if 'celery' in filename:
                return True
        return False

    assert test_if_running_as_celery_worker()

    # Dummy request object, it is used in serialization to get JSONP callback name, but we
    # want always just JSON, so we can create dummy object and hopefuly get away with it
    request = client.RequestFactory().request()

    from piplmesh import urls

    bundle = urls.notification_resource.build_bundle(obj=notification, request=request)
    output_bundle = urls.notification_resource.full_dehydrate(bundle)
    output_bundle = urls.notification_resource.alter_detail_data_to_serialize(request, output_bundle)

    serialized = urls.notification_resource.serialize(request, {
        'type': 'notification',
        'notification': output_bundle.data,
    }, 'application/json')
    updates.send_update(notification.recipient.get_user_channel(), serialized, True)

def panels_collapse(request):
    if request.method == 'POST':
        request.user.panels_collapsed[request.POST['name']] = True if request.POST['collapsed'] == 'true' else False
        request.user.save()
        return http.HttpResponse()
    else:
        return http.HttpResponse(simplejson.dumps(request.user.panels_collapsed), mimetype='application/json')

def panels_order(request):
    if request.method == 'POST':
        panels = []

        for name, column in zip(request.POST.getlist('names'), request.POST.getlist('columns')):
            column = int(column)
            if column == len(panels):
                panels.append([])
            panels[column].append(name)

        request.user.panels_order[request.POST['number_of_columns']] = panels
        request.user.save()

        return http.HttpResponse()
    else:
        number_of_columns = request.GET['number_of_columns']
        panels = request.user.panels_order.get(number_of_columns, [])
        return http.HttpResponse(simplejson.dumps(panels), mimetype='application/json')
