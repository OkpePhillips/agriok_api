from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView,
    EmailLoginView,
    ProfileView,
    UpdateProfileView,
    FarmInsightAPIView,
    FarmInsightDetailAPIView,
    ProductAPIView,
    ProductDetailAPIView,
    ChangePasswordView,
    AddToCartView,
    CartView,
    PlaceOrderView,
    OrderHistoryView,
    InitializePaymentView,
    VerifyPaymentView,
)


urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", EmailLoginView.as_view(), name="login"),
    path("insights/", FarmInsightAPIView.as_view(), name="farm-insights"),
    path(
        "insights/<int:pk>/",
        FarmInsightDetailAPIView.as_view(),
        name="farm-insight-detail",
    ),
    path("products/", ProductAPIView.as_view(), name="products"),
    path("products/<int:pk>/", ProductDetailAPIView.as_view(), name="product-detail"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("profile/update/", UpdateProfileView.as_view(), name="update-profile"),
    path(
        "profile/change-password/", ChangePasswordView.as_view(), name="change-password"
    ),
    path("cart/", CartView.as_view(), name="cart"),
    path("cart/add/", AddToCartView.as_view(), name="add-to-cart"),
    path("order/place/", PlaceOrderView.as_view(), name="place-order"),
    path("order/history/", OrderHistoryView.as_view(), name="order-history"),
    path(
        "payment/initialize/",
        InitializePaymentView.as_view(),
        name="initialize-payment",
    ),
    path(
        "payment/verify/<str:reference>/",
        VerifyPaymentView.as_view(),
        name="verify-payment",
    ),
]
