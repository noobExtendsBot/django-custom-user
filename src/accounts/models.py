"""
    accounts aap will have 6 models
    1- Role
    2- User
    3
    4
    5
    6
"""

from django.db import models
from django.core.validators import RegexValidator
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin
)


class Role(models.Model):
    """
        INITIALLY 5 ROLES FOR ALL TYPES OF USER

        (key)        (val)
        SUPER_ADMIN = 1
        WORKER_ADMIN = 2
        RIDER = 3
        DRIVER = 4
        CAR_OWNER = 5

        While creating User we pass a value corresponding to key and create get a object with that key and assign to new User created.
        Example: roles = Role.objects.get(id=val)
                 u.roles.set([roles]) or user.roles.set([roles]) while creating user in User model.

        **WARNING** : Initially we will have to manually create objects with val.
                      Example: r_obj = Role.objects.create(id=1)            [and rest of the id similarly]

        INTIALLY 1 METHOD

        1- def __str__(self): to return the object Name
    """
    SUPER_ADMIN = 1
    WORKER_ADMIN = 2
    RIDER = 3
    DRIVER = 4
    CAR_OWNER = 5

    ROLE_CHOICES = (
        (SUPER_ADMIN, 'super_admin'),
        (WORKER_ADMIN, 'worker_admin'),
        (RIDER, 'rider'),
        (DRIVER, 'driver'),
        (CAR_OWNER, 'car_owner'),
    )

    id = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, primary_key=True)

    def __str__(self):
        return self.get_id_display()

class UserManager(BaseUserManager):
    """
        CUSTOM UserManager To handle user creation and superuser creation.
        INITIALLY 2 methods

        1- create_user() accepts all parameters which are REQUIRED_FIELDS
        2- create_superuser() to create a SuperUser

        **WARNING**: In create_user roles for specific user will be set after User has been saved to database and we have to use set(). Which accepts list of args eg: set([value])
    """
    def create_user(self, phone_number, roles, password=None):
        if roles is None:
            roles = 3
        if not phone_number:
            raise ValueError('Phone number must be set')
        
        if not password:
            raise ValueError('Password must be set')
        roles = Role.objects.get(id=roles)
        print(roles)
        user = self.model(phone_number=phone_number)                                                                                                                                       # pass fields as arguments which are REQUIRED_FIELDS to user = self.model()                                                                                                                      
        user.set_password(password)                                                                                                                                                                            # user.set_password(password) to change the password
        user.save(using=self._db)
        user.roles.set([roles])
        return user
    
    def create_superuser(self, phone_number, password):
        roles = 1
        user = self.create_user(
            phone_number,
            roles,
            password=password,
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    """
        INITIALLY 7 FIELDS

        1- phone_number as a USERNAME_FIELD
        2- roles a ManyToManyField to Role; such that User can have multiple roles.
        3- is_active a BooleanField to check if a user can log in or not
        4- is_staff a BooleanField. If set 'True' USER will be able to login in Admin section (edit will depend upon user_permissions field)
        5- is_superuser a BooleanField only used while creating SuperUser with all permissions.
        6- created_timestamp time of the user created.
        7- last_login timestamp to check last login of user.

        INTIALLY 5 METHOD

        1- __str__(self): To return Object Name (which is phone_number)
        2- get_full_name(): Returns phone_number itself [**MAY GET REMOVED IN FUTURE**]

    """
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$', message="Phone number must be entered in the format: '+919939799264'. Up to 15 digits allowed.")                                                  # phone_number max length 15 including country code
    phone_number = models.CharField(validators=[phone_regex], max_length=15, unique=True, null=False, blank=False)                                                                                           # unique=True (each phone number should be unique), validators should be a list         
    roles = models.ManyToManyField(Role,  default=3)                                                                                                                                                         # default 3 which is rider; an object of Role.objects.get(id=3)
    is_active = models.BooleanField(default=True, null=False, blank=False)                                                                                                                                   # is_active=True by default. User should be able to login
    is_staff = models.BooleanField(default=False, null=False, blank=False)                                                                                                                                   # is_staff=False by default. No staff user
    is_superuser = models.BooleanField(default=False, null=False, blank=False)                                                                                                                               # is_superuser=False for normal users, except ADMIN; This may change is future based ON ROLES                                               
    created_timestamp = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'phone_number'                                                                                                                                                                          # set USERNAME_FIELD to phone_number
    REQUIRED_FIELDS = []                                                                                                                                                                            # REQUIRED_FILEDS takes a list of required field. PASSWORD AND USERNAME_FILED by default are REQUIRED_FIELDS
    objects = UserManager()

    def __str__(self):
        return self.phone_number
    
    def get_full_name(self):
        return self.phone_number
    
    # def get_short_name(self):
    #     return self.phone_number
    
    # def has_perm(self, perm, obj=None):
    #     return True

    # def has_module_perms(self, app_label):
    #     return True
    
class CarOwnerProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='car_owner_profile')
    first_name = models.CharField(max_length=25, blank=True)
    middle_name = models.CharField(max_length=25, blank=True)
    las_name = models.CharField(max_length=25, blank=True)

class DriverProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='driver_profile')
    first_name = models.CharField(max_length=25, blank=True)
    middle_name = models.CharField(max_length=25, blank=True)
    las_name = models.CharField(max_length=25, blank=True)

class RiderProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='rider_profile')
    first_name = models.CharField(max_length=25, blank=True)
    middle_name = models.CharField(max_length=25, blank=True)
    las_name = models.CharField(max_length=25, blank=True)

# @receiver(post_save, sender=User)
# def create_user_profile(sender, instance, created, **kwargs):
#     print("****", created)
#     if instance.is