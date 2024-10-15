from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("signup/", views.signup, name="signup"),
    path("signin/", views.signin, name="signin"),
    path("userlogout/", views.userlogout, name="userlogout"),
    path("fashionlist/", views.fashionlist, name="fashionlist"),
    path("shoeslist/", views.shoeslist, name="shoeslist"),
    path("mobilelist/", views.mobilelist, name="mobilelist"),
    path("electronicslist/", views.electronicslist, name="electronicslist"),
    path("clothlist/", views.clothlist, name="clothlist"),
    path("grocerylist/", views.grocerylist, name="grocerylist"),
    path("searchproduct/", views.searchproduct, name="searchproduct"),
    path(
        "request_password_reset/",
        views.request_password_reset,
        name="request_password_reset",
    ),
    path("reset_password/<username>/", views.reset_password, name="reset_password"),
]
