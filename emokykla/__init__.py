"""Main entry point
"""
from pyramid.config import Configurator

from webassets import Bundle

class TextRenderer(object):

    def __init__(self, info):
        pass

    def __call__(self, value, system):
        request = system.get('request')
        if request is not None:
            response = request.response
            response.content_type = 'text/plain'
        name = value["output"]
        return u"{}".format(name)


def main(global_config, **settings):
    config = Configurator(settings=settings)

    config.include("cornice")
    config.scan("emokykla.auth")  # /login, /logout, /register etc.
    config.scan("emokykla.user")  # /users/<uid>...
    config.scan("emokykla.organization")  # /orgs/<orgid>...

    config.add_renderer('text', TextRenderer)

    config.include('pyramid_webassets')
    static = Bundle('/*.html', debug=True)
    config.add_webasset('static', static)

    return config.make_wsgi_app()
