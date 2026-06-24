from django import forms


class LoginForm(forms.Form):
    handle = forms.CharField(
        label="Your Handle",
        max_length=253,
        widget=forms.TextInput(attrs={"placeholder": "alice.myatproto.social"}),
    )
