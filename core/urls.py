from django.urls import path

from . import views

urlpatterns = [
    path('ping/', views.ping, name='ping'),
    path('model_get_score/', views.model_get_score, name='model_get_score'),
    path('model_get_score/<path:url_value>', views.model_get_score, name='model_get_score_single'),
    path('safe_search_score/', views.safe_search_score, name='safe_search_score'),
    path('safe_search_score/<path:url_value>', views.safe_search_score, name='safe_search_score_single'),
]
