import datetime

from django.utils import timezone

from celery import task

from mongo_auth import backends

from pushserver.utils import updates

from piplmesh.account import models
from piplmesh.utils import decorators

HOME_CHANNEL_ID = 'home'
CHECK_ONLINE_USERS_INTERVAL = 10 # seconds
CHECK_ONLINE_USERS_RECONNECT_TIMEOUT = 2 * CHECK_ONLINE_USERS_INTERVAL

@task.periodic_task(run_every=datetime.timedelta(seconds=CHECK_ONLINE_USERS_INTERVAL))
@decorators.single_instance_task(timeout=10 * CHECK_ONLINE_USERS_INTERVAL) # Maximum time for one task to finish is 10x the interval
def check_online_users():
    for user in backends.User.objects(
        is_online=False,
        connections__not__in=([], None), # None if field is missing altogether, not__in seems not to be equal to nin
    ):
        if backends.User.objects(
            pk=user.pk,
            is_online=False,
            connections__not__in=([], None), # None if field is missing altogether, not__in seems not to be equal to nin
        ).update(set__is_online=True):
            updates.send_update(
                HOME_CHANNEL_ID,
                {
                    'type': 'user_connect',
                    'user': {
                        'username': user.username,
                        'profile_url': user.get_profile_url(),
                        'image_url': user.get_image_url(),
                    },
                }
            )

    for user in backends.User.objects(
        is_online=True,
        connections__in=([], None), # None if field is missing altogether
        connection_last_unsubscribe__lt=timezone.now() - datetime.timedelta(seconds=CHECK_ONLINE_USERS_RECONNECT_TIMEOUT),
    ):
        if backends.User.objects(
            pk=user.pk,
            is_online=True,
            connections__in=([], None), # None if field is missing altogether
            connection_last_unsubscribe__lt=timezone.now() - datetime.timedelta(seconds=CHECK_ONLINE_USERS_RECONNECT_TIMEOUT),
        ).update(set__is_online=False):
            # On user disconnect we cycle channel_id, this is to improve security if somebody
            # intercepted current channel_id as there is no authentication on HTTP push channels
            # This is the best place to cycle channel_id as we know that user does not listen
            # anymore to any channel
            user.reload()
            user.channel_id = models.generate_channel_id()
            user.save()

            updates.send_update(
                HOME_CHANNEL_ID,
                {
                    'type': 'user_disconnect',
                    'user': {
                        'username': user.username,
                        'profile_url': user.get_absolute_url(),
                        'image_url': user.get_image_url(),
                    },
                }
            )

@task.task
def send_update_on_published_post(serialized_update):
    updates.send_update(HOME_CHANNEL_ID, serialized_update, True)
