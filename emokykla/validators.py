"""
Common request validators and request filters.

Difference between the two is that request filters are liable for filling the
request.validated dictionary parameters.
"""


def v_required(*params):
    def required(request):
        try:
            jb = request.json_body
        except ValueError:
            request.errors.add('v_required', 'EPARAMS',
                               'ValueError while parsing JSON request body')
            return
        for k in params:
            if k not in jb:
                request.errors.add('v_required', 'EPARAMS',
                                   'Request parameter `{}` is required'\
                                   .format(k))
    return required
