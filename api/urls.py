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
    CartDetailAPIView,
    PlaceOrderView,
    OrderHistoryView,
    UserAPIView,
    FarmlandAPIView,
    FarmlandDetailAPIView,
    TransactionView,
    LogoutView,
    MTNMomoPaymentView,
    VerifyPaymentView,
    GetProductView,
)


urlpatterns = [
    path("register", RegisterView.as_view(), name="register"),
    path("login", EmailLoginView.as_view(), name="login"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("insights", FarmInsightAPIView.as_view(), name="farm-insights"),
    path(
        "insights/<int:pk>",
        FarmInsightDetailAPIView.as_view(),
        name="farm-insight-detail",
    ),
    path("products/create", ProductAPIView.as_view(), name="create-products"),
    path("products", GetProductView.as_view(), name="products"),
    path("products/<int:pk>", ProductDetailAPIView.as_view(), name="product-detail"),
    path("profile", ProfileView.as_view(), name="profile"),
    path("profile/update", UpdateProfileView.as_view(), name="update-profile"),
    path(
        "profile/change-password", ChangePasswordView.as_view(), name="change-password"
    ),
    path("cart/<int:pk>", CartDetailAPIView.as_view(), name="cart"),
    path("cart", CartDetailAPIView.as_view(), name="Get-cart"),
    path("cart/add", AddToCartView.as_view(), name="add-to-cart"),
    path("order/place", PlaceOrderView.as_view(), name="place-order"),
    path("order/history", OrderHistoryView.as_view(), name="order-history"),
    path("users", UserAPIView.as_view(), name="users"),
    path("users/<int:pk>", UserAPIView.as_view(), name="users"),
    path("farmlands", FarmlandAPIView.as_view(), name="farmlands"),
    path("farmlands/<int:pk>", FarmlandDetailAPIView.as_view(), name="farmland"),
    path("transactions", TransactionView.as_view(), name="transactions"),
    path(
        "transactions/<uuid:pk>", TransactionView.as_view(), name="transaction-detail"
    ),
    path("payment", MTNMomoPaymentView.as_view(), name="mtn_momo_payment"),
    path("verify-payment", VerifyPaymentView.as_view(), name="verify_payment"),
]
