import random

from django.contrib.webdesign import lorem_ipsum
from django.utils.translation import ugettext_lazy as _

from piplmesh import panels

class DummyPanel2(panels.BasePanel):
    def get_context(self, context):
        context.update({
            'header': _("Dummy panel 2"),
            'content': '\n\n'.join(lorem_ipsum.paragraphs(random.randint(1, 1))),
            'id': 'dummy2',
        })
        return context

panels.panels_pool.register(DummyPanel2)
