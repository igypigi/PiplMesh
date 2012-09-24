import traceback

from django import dispatch, http, template
from django.conf import settings
from django.contrib import messages
from django.core import mail, urlresolvers
from django.core.files import storage
from django.test import client
from django.utils import simplejson
from django.utils.translation import ugettext_lazy as _
from django.views import generic as generic_views

from mongoengine import signals as mongoengine_signals

from tastypie import http as tastypie_http

from mongogeneric import detail

from pushserver.utils import updates
from tastypie.utils import formatting

from piplmesh.account import models as account_models
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

    template_name = 'user/user.html'
    document = account_models.User
    slug_field = 'username'
    slug_url_kwarg = 'username'

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

def forbidden_view(request, reason=''):
    """
    Displays 403 forbidden page. For example, when request fails CSRF protection.
    """

    from django.middleware import csrf
    t = template.loader.get_template('403.html')
    return http.HttpResponseForbidden(t.render(template.RequestContext(request, {
        'DEBUG': settings.DEBUG,
        'reason': reason,
        'no_referer': reason == csrf.REASON_NO_REFERER,
    })))

@dispatch.receiver(signals.post_created)
def send_update_on_new_post(sender, post, request, bundle, **kwargs):
    """
    Sends update through push server when a new post is created.
    """
    if post.is_published:
        output_bundle = sender.full_dehydrate(bundle)
        output_bundle = sender.alter_detail_data_to_serialize(request, output_bundle)

        serialized_update = sender.serialize(request, {
            'type': 'post_new',
            'post': output_bundle.data,
        }, 'application/json')

        # We send update asynchronously as it could block and we
        # want REST request to finish quick
        tasks.send_update_on_new_post.delay(serialized_update)

@mongoengine_signals.post_save.connect_via(sender=api_models.Notification)
def send_update_on_new_notification(sender, document, created, **kwargs):
    """
    Sends update through push server to the user when a new notification is created.

    Important: This signal should be processed only asynchronously (background task) as
    it can block. So currently it is assumed that notification documents are created
    only in background tasks.
    """

    notification = document

    def test_if_running_as_celery_worker():
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

@dispatch.receiver(signals.post_updated)
def send_update_on_updated_post(sender, post, request, bundle, **kwargs):
    """
    Sends update to push server when a post is updated.
    """
    if post.is_published:
        hugs = []
        for hug in post.hugs:
            hugs.append(hug.username)
        runs = []
        for run in post.runs:
            runs.append(run.username)
        update = {
            'type': 'post_update',
            'post': {
                'id': post.id.__str__(),
                'author': {
                    'username': post.author.username,
                },
                'message': post.message,
                'hugs': hugs,
                'runs': runs,
                'updated_time': formatting.rfc2822_date(post.updated_time),
                'created_time': formatting.rfc2822_date(post.created_time),
            }
        }

        updates.send_update(HOME_CHANNEL_ID, update, False)

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

def hug_run(request):
    """
    Process clicks on Hug and Run buttons
    """
    if request.method == 'POST':
        type = request.POST['type']
        id = request.POST['id']
        post = api_models.Post.objects.get(pk=id)
        user = request.user
        if type == 'hug':
            if user not in post.hugs:
                post.hugs.append(user)
            if user in post.runs:
                post.runs.remove(user)
            post.save()
        elif type == 'unhug':
            if user in post.hugs:
                post.hugs.remove(user)
            post.save()
        elif type == 'run':
            if user not in post.runs:
                post.runs.append(user)
            if user in post.hugs:
                post.hugs.remove(user)
            post.save()
        elif type == 'unrun':
            if user in post.runs:
                post.runs.remove(user)
            post.save()
        else:
            return http.HttpResponseBadRequest()
        signals.post_updated.send(sender=None, post=post, request=request, bundle=None)
        return http.HttpResponse()
    return http.HttpResponseBadRequest()
