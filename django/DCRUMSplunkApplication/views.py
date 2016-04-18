from django.contrib.auth.decorators import login_required
from splunkdj.decorators.render import render_to

@render_to('dcrum:home.html')
@login_required
def home(request):
    return {
        "message": "Welcome to the DC RUM example Splunk app!",
        "app_name": "dcrum"
    }