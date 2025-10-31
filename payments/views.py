from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.db.models import Q, Sum, Count
from django.utils import timezone
import logging
import json
import os
from pathlib import Path
from datetime import datetime

from .models import H5App, Payment, PaymentCallbackLog
from .serializers import (
    H5AppSerializer, H5AppCreateSerializer, PaymentSerializer,
    PaymentCallbackSerializer, PaymentCallbackLogSerializer, PaymentStatsSerializer
)
from .services import DecryptionService

logger = logging.getLogger('payments')


class H5AppListCreateView(generics.ListCreateAPIView):
    """
    List all H5 apps or create a new one
    GET /api/h5-apps/ - List all H5 apps
    POST /api/h5-apps/ - Create a new H5 app
    """
    queryset = H5App.objects.all()
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_serializer_class(self):
        if self.request.method == 'POST':
            return H5AppCreateSerializer
        return H5AppSerializer
    
    def get_queryset(self):
        queryset = H5App.objects.all()
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by name or app_key
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(app_key__icontains=search)
            )
        
        return queryset.order_by('-created_at')


class H5AppRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a specific H5 app
    GET /api/h5-apps/{id}/ - Get H5 app details
    PUT /api/h5-apps/{id}/ - Update H5 app
    PATCH /api/h5-apps/{id}/ - Partial update H5 app
    DELETE /api/h5-apps/{id}/ - Delete H5 app
    """
    queryset = H5App.objects.all()
    serializer_class = H5AppSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    lookup_field = 'id'


class H5AppPaymentsView(generics.ListAPIView):
    """
    Get all payments for a specific H5 app
    GET /api/h5-apps/{id}/payments/ - List payments for H5 app
    """
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        h5_app_id = self.kwargs['id']
        h5_app = get_object_or_404(H5App, id=h5_app_id)
        
        queryset = Payment.objects.filter(h5_app=h5_app)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
        
        return queryset.order_by('-created_at')


class PaymentListCreateView(generics.ListCreateAPIView):
    """
    List all payments or create a new one
    GET /api/payments/ - List all payments
    POST /api/payments/ - Create a new payment
    """
    queryset = Payment.objects.select_related('h5_app').all()
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        queryset = Payment.objects.select_related('h5_app').all()
        
        # Filter by H5 app
        h5_app_id = self.request.query_params.get('h5_app')
        if h5_app_id:
            queryset = queryset.filter(h5_app_id=h5_app_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by payment reference
        payment_ref = self.request.query_params.get('payment_ref')
        if payment_ref:
            queryset = queryset.filter(payment_ref__icontains=payment_ref)
        
        return queryset.order_by('-created_at')


class PaymentRetrieveView(generics.RetrieveAPIView):
    """
    Retrieve a specific payment
    GET /api/payments/{id}/ - Get payment details
    """
    queryset = Payment.objects.select_related('h5_app').all()
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    lookup_field = 'id'


@api_view(['POST'])
@permission_classes([AllowAny])
def payment_callback(request):
    """
    Handle SuperApp payment callback
    POST /api/payment/callback/ - Receive payment notification from SuperApp
    """
    # Log the payload to console
    logger.info(f"Callback payload: {request.data}")
    
    # Save payload to JSON file in callback-payload folder
    try:
        # Get base directory (project root)
        from django.conf import settings
        callback_dir = Path(settings.BASE_DIR) / 'callback-payload'
        
        # Create directory if it doesn't exist
        callback_dir.mkdir(exist_ok=True)
        
        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # Include milliseconds
        filename = f"callback_{timestamp}.json"
        filepath = callback_dir / filename
        
        # Convert request.data to dict if needed (it might be a QueryDict)
        if hasattr(request.data, 'dict'):
            payload_data = request.data.dict()
        else:
            payload_data = dict(request.data)
        
        # Add metadata to the saved payload
        saved_data = {
            "timestamp": datetime.now().isoformat(),
            "received_at": timezone.now().isoformat(),
            "payload": payload_data
        }
        
        # Save as JSON file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(saved_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Callback payload saved to: {filepath}")
        
    except Exception as e:
        logger.error(f"Error saving callback payload to file: {str(e)}")
    
    return Response({"code": "SUCCESS"}, status=status.HTTP_200_OK)


class PaymentStatsView(APIView):
    """
    Get payment statistics
    GET /api/payments/stats/ - Get overall payment statistics
    GET /api/payments/stats/?h5_app_id={id} - Get stats for specific H5 app
    """
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get(self, request):
        h5_app_id = request.query_params.get('h5_app_id')
        
        # Base queryset
        if h5_app_id:
            queryset = Payment.objects.filter(h5_app_id=h5_app_id)
        else:
            queryset = Payment.objects.all()
        
        # Calculate statistics
        stats = {
            'total_payments': queryset.count(),
            'completed_payments': queryset.filter(status='completed').count(),
            'pending_payments': queryset.filter(status='pending').count(),
            'failed_payments': queryset.filter(status='failed').count(),
            'total_amount': queryset.aggregate(total=Sum('amount'))['total'] or 0,
            'completed_amount': queryset.filter(status='completed').aggregate(
                total=Sum('amount')
            )['total'] or 0,
        }
        
        serializer = PaymentStatsSerializer(stats)
        return Response(serializer.data)


class PaymentCallbackLogsView(generics.ListAPIView):
    """
    Get payment callback logs for debugging
    GET /api/payments/callback-logs/ - List all callback logs
    GET /api/payments/callback-logs/?payment_id={id} - Filter by payment
    """
    serializer_class = PaymentCallbackLogSerializer
    permission_classes = [AllowAny]  # Adjust permissions as needed
    
    def get_queryset(self):
        queryset = PaymentCallbackLog.objects.select_related('payment').all()
        
        # Filter by payment ID
        payment_id = self.request.query_params.get('payment_id')
        if payment_id:
            queryset = queryset.filter(payment_id=payment_id)
        
        # Filter by success status
        is_successful = self.request.query_params.get('is_successful')
        if is_successful is not None:
            queryset = queryset.filter(is_successful=is_successful.lower() == 'true')
        
        return queryset.order_by('-received_at')