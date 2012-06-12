from django.utils.translation import ugettext_lazy as _

from piplmesh import panels
from piplmesh.account import models

class OnlineUsersPanel(panels.BasePanel):
    def get_context(self, context):
        context.update({
            'header': _("Online users"),
            'online_users': models.User.objects(is_online=True),
            'id': 'online_users',
        })
        return context

panels.panels_pool.register(OnlineUsersPanel)
