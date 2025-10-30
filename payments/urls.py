from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router for automatic URL routing (if using ViewSets)
router = DefaultRouter()

# Define URL patterns
urlpatterns = [
    # H5 App CRUD endpoints
    path('h5-apps/', views.H5AppListCreateView.as_view(), name='h5app-list-create'),
    path('h5-apps/<uuid:id>/', views.H5AppRetrieveUpdateDestroyView.as_view(), name='h5app-detail'),
    path('h5-apps/<uuid:id>/payments/', views.H5AppPaymentsView.as_view(), name='h5app-payments'),
    
    # Payment endpoints
    path('payments/', views.PaymentListCreateView.as_view(), name='payment-list-create'),
    path('payments/<uuid:id>/', views.PaymentRetrieveView.as_view(), name='payment-detail'),
    path('payments/stats/', views.PaymentStatsView.as_view(), name='payment-stats'),
    path('payments/callback-logs/', views.PaymentCallbackLogsView.as_view(), name='payment-callback-logs'),
    
    # SuperApp callback endpoint
    path('payment/callback/', views.payment_callback, name='payment-callback'),
]

