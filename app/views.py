from django.shortcuts import render, redirect
from .models import Product, Cart, Orders, Address, Payment
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout

# Create your views here.


def index(req):
    allproducts = Product.objects.all()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


from django.core.exceptions import ValidationError


def validate_password(password):
    # Check minimum length
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")

    # Check maximum length
    if len(password) > 128:
        raise ValidationError("Password cannot exceed 128 characters.")

    # Initialize flags for character checks
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    special_characters = "@$!%*?&"

    # Check for character variety
    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif char in special_characters:
            has_special = True

    if not has_upper:
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not has_lower:
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not has_digit:
        raise ValidationError("Password must contain at least one digit.")
    if not has_special:
        raise ValidationError(
            "Password must contain at least one special character (e.g., @$!%*?&)."
        )

    # Check against common passwords
    common_passwords = [
        "password",
        "123456",
        "qwerty",
        "abc123",
    ]  # Add more common passwords
    if password in common_passwords:
        raise ValidationError("This password is too common. Please choose another one.")


def signup(req):
    if req.method == "POST":
        uname = req.POST["uname"]
        email = req.POST["email"]
        upass = req.POST["upass"]
        ucpass = req.POST["ucpass"]
        context = {}
        try:
            validate_password(upass)
        except ValidationError as e:
            context["errmsg"] = str(e)
            return render(req, "signup.html", context)

        if uname == "" or email == "" or upass == "" or ucpass == "":
            context["errmsg"] = "Field can't be empty"
            return render(req, "signup.html", context)
        elif upass != ucpass:
            context["errmsg"] = "Password and confirm password doesn't match"
            return render(req, "signup.html", context)
        elif uname.isdigit():
            context["errmsg"] = "Username cannot consist solely of numbers."
            return render(req, "signup.html", context)
        else:
            try:
                userdata = User.objects.create(
                    username=uname, email=email, password=upass
                )
                userdata.set_password(upass)
                userdata.save()
                return redirect("/signin")
            except:
                context["errmsg"] = "User Already exists"
                return render(req, "signup.html", context)
    else:
        context = {}
        context["errmsg"] = ""
        return render(req, "signup.html", context)


def signin(req):
    if req.method == "POST":
        email = req.POST["email"]
        upass = req.POST["upass"]
        context = {}
        if email == "" or upass == "":
            context["errmsg"] = "Field can't be empty"
            return render(req, "signin.html", context)
        else:
            user = User.objects.get(email=email)  # Retrieve user by email
            userdata = authenticate(username=user.username, password=upass)
            print(userdata)
            if userdata is not None:
                login(req, userdata)
                return redirect("/")
            else:
                context["errmsg"] = "Invalid username and password"
                return render(req, "signin.html", context)
    else:
        return render(req, "signin.html")


def userlogout(req):
    logout(req)
    return redirect("/")


from django.contrib import messages


def request_password_reset(req):
    if req.method == "POST":
        email = req.POST.get("email")
        context = {}

        # Check if the email exists
        try:
            user = User.objects.get(email=email)
            # Redirect to the password reset page
            return redirect("reset_password", username=user.username)
        except User.DoesNotExist:
            context["errmsg"] = "No account found with that email."
            return render(req, "request_password_reset.html", context)

    return render(req, "request_password_reset.html")


def reset_password(req, username):
    try:
        user = User.objects.get(username=username)

        if req.method == "POST":
            new_password = req.POST.get("new_password")
            try:
                validate_password(new_password)
                user.set_password(new_password)  # Hash the password
                user.save()
                messages.success(req, "Your password has been reset successfully.")
                return redirect(
                    "signin"
                )  # Redirect to the signin page after successful reset

            except ValidationError as e:
                messages.error(req, str(e))  # Show the validation error message
                return render(
                    req, "reset_password.html", {"username": username}
                )  # Stay on the same page

        return render(req, "reset_password.html", {"username": username})

    except User.DoesNotExist:
        messages.error(req, "User not found.")
        return redirect("request_password_reset")


def fashionlist(req):
    allproducts = Product.productmanager.fashion_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def shoeslist(req):
    allproducts = Product.productmanager.shoes_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def mobilelist(req):
    allproducts = Product.productmanager.mobile_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def electronicslist(req):
    allproducts = Product.productmanager.electronics_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def clothlist(req):
    allproducts = Product.productmanager.cloth_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def grocerylist(req):
    allproducts = Product.productmanager.grocery_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


from django.db.models import Q


def searchproduct(req):
    query = req.GET.get("q")
    errmsg = ""
    if query:
        allproducts = Product.objects.filter(
            Q(productname__icontains=query)
            | Q(category__icontains=query)
            | Q(description__icontains=query)
        )
        if len(allproducts) == 0:
            errmsg = "No result found!!"

    else:
        allproducts = Product.objects.all()

    context = {"allproducts": allproducts, "errmsg": errmsg}
    return render(req, "index.html", context)
