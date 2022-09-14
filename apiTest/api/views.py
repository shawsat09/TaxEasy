from django.shortcuts import render

# Create your views here.

from rest_framework.response import Response
from rest_framework.views import APIView
from passlib.hash import pbkdf2_sha256
# from userProfile.serializers import UserSerializer
import django.db
import re
import jwt
# from userProfile.models import UserProfile
import logging
import datetime
logger = logging.getLogger('django')


class UserCreations(APIView):
    @staticmethod
    def post(request):
        try:
            logger.info('This is the API for User Creations')
            json_data = request.data
            print(json_data)
            name = json_data['name']
            # if not name.isalpha():
            #     message = "name is not valid, Should contain only alphabets"
            #     final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
            #     logger.error(message)
            #     return Response(final_dict, 400)
            mobile_num = json_data['Phone number']
            if len(mobile_num) != 10:
                message = "Enter only 10 digit mobile number"
                final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)
            elif not mobile_num.isnumeric():
                message = "Enter only 10 digit mobile number"
                final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)
            # user_category = json_data['user_category']
            # if not user_category:
            user_category = 'normal user'
            email = json_data['email'].lower()
            regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
            if re.search(regex, email):
                email = email
            else:
                message = "Please enter a valid emailid"
                final_dict = {'data': email, 'message': message, 'status': 'error'}
                logger.error(message)
                return Response(final_dict, 400)
            pan_number = json_data['pan_number']
            pan_regex = '^[a-zA-Z]{5}[0-9]{4}[a-zA-Z]{1}$'
            if re.search(pan_regex, pan_number):
                pan_number = pan_number
            password = json_data['password']

            if len(password) < 8:
                message = "Password must be more than 8 characters"
                final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)

            confirm_password = json_data['confirm_password']
            reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
            # compiling regex
            pat = re.compile(reg)
            # searching regex
            mat = re.search(pat, password)
            # validating conditions
            if mat:
                if password == confirm_password:
                    encrypted_pwd = pbkdf2_sha256.encrypt(password, rounds=12000, salt_size=32)

                    data1 = {'Name': name,'mobile_num': mobile_num,'pan_number': pan_number,
                             'email': email,
                             'password': encrypted_pwd, 'user_category': user_category}

                    # data = UserSerializer(data=data1)
                    token = ''
                    try:
                        created = True
                        # data.save()
                        id = 1
                        message = 'success'
                        logger.info("User created successfully")
                        status_code = 201
                        payload = {
                            'id': 1,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                            'iat': datetime.datetime.utcnow(),
                            'paid': True
                        }
                        # token = jwt.encode(payload, 'secret', algorithm='HS256')
                        token = 'justfortest'
                    except (TypeError, ValueError):
                        created = False
                        id = None
                        message = 'check the data'
                        logger.error(message)
                        logger.exception(TypeError, ValueError)
                        status_code = 400
                    except django.db.IntegrityError:
                        created = False
                        message = 'Data already present -IntegrityError'
                        id = None
                        logger.error(message)
                        status_code = 400
                    # if data.is_valid():
                    #     try:
                    #         created = True
                    #         data.save()
                    #         id = UserProfile.objects.get(email=email).user_id
                    #         message = 'success'
                    #         logger.info("User created successfully")
                    #         status_code = 201
                    #         payload = {
                    #             'id': UserProfile.objects.get(email=email).user_id,
                    #             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                    #             'iat': datetime.datetime.utcnow(),
                    #             'paid': True
                    #         }
                    #         token = jwt.encode(payload, 'secret', algorithm='HS256')
                    #     except (TypeError, ValueError):
                    #         created = False
                    #         id = None
                    #         message = 'check the data'
                    #         logger.error(message)
                    #         logger.exception(TypeError, ValueError)
                    #         status_code = 400
                    #     except django.db.IntegrityError:
                    #         created = False
                    #         message = 'Data already present -IntegrityError'
                    #         id = None
                    #         logger.error(message)
                    #         status_code = 400
                    # else:
                    #     print(data.errors)
                    #     created = False
                    #     message = data.errors
                    #     id = None
                    #     status_code = 400
                    #     logger.error(message)

                    final_dict = {'created': created, 'id': id, 'message': message, 'status': status_code, 'jwt': token}
                    return Response(final_dict, status_code)

                else:
                    message = "Password did not match"
                    final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
                    logger.error(message)
                    return Response(final_dict, 400)

            else:
                message = "Please enter a valid password(must include alphabets with Upper case,lower case ,a number and " \
                          "a special character "
                final_dict = {'created': False, 'id': None, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)
        except Exception as e:
            final_dict = {'created': False, 'id': None,'message': str(e),'status': 'error','jwt': None}
            return Response(final_dict, 400)


class UserLogin(APIView):
    @staticmethod
    def post(request):
        try:
            logger.info('This is the API for User Login')
            json_data = request.data
            print(json_data)
            user_name = json_data['username']
            id = ''
            mobile_num = ''
            mail_id = ''

            if user_name.isnumeric() and len(user_name) == 10:
                mobile_num = user_name
            elif re.search('^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', user_name):
                mail_id = user_name
            elif re.search('^[a-zA-Z]{5}[0-9]{4}[a-zA-Z]{1}$', user_name):
                pan_number = user_name
            else:
                message = "Please enter a valid username"
                final_dict = {'login': False, 'id': id, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)
            password = json_data['password']
            if len(password) < 8:
                message = "Password must be more than 8 characters"
                final_dict = {'login': False, 'id': id, 'message': message, 'status': 'error', 'jwt': None}
                logger.error(message)
                return Response(final_dict, 400)

            id = 1
            login = True
            message = 'login_successful'
            status_code = 200
            jwt = 'justfortest'
            status = 'success'
            final_dict = {'login': login, 'id': id, 'message': message, 'status': status, 'jwt': jwt}
            return Response(final_dict,201)

        #     try:
        #         if mobile_num:
        #             check_password = 'check password'
        #             id = 1
        #         elif mail_id:
        #             check_password = 'checlk email'
        #             id = 1
        #         elif pan_number:
        #             check_password = 'check pan'
        #             id = 1
        #         else:
        #             message = "user not exist"
        #             final_dict = {'login': False, 'id': id, 'message': message, 'status': 'error', 'jwt': None}
        #             logger.error(message)
        #             return Response(final_dict, 400)
        #     except Exception as e:
        #         import traceback
        #         traceback.print_exc()
        #         message = "user not exist"
        #         logger.exception(str(e), exc_info=True)
        #         logger.error(message)
        #         final_dict = {'login': False, 'id': id, 'message': message, 'status': 'error', 'jwt': None}
        #         return Response(final_dict, 400)
        #     # if check_password is None or check_password == '':
        #     #     message = "user is not active, Please contact administrator"
        #     #     final_dict = {'login': False, 'id': id, 'message': message, 'status': 'error', 'jwt': None}
        #     #     logger.error(message)
        #     #     return Response(final_dict, 400)
        #     if pbkdf2_sha256.verify(password, check_password):
        #         login = True
        #         id = id
        #         message = 'login_successful'
        #         status_code = 200
        #         status = 'success'
        #         logger.info("Login Successful")
        #         payload = {
        #             'id': id,
        #             'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        #             'iat': datetime.datetime.utcnow(),
        #             'paid': True
        #         }
        #         token = jwt.encode(payload, 'secret', algorithm='HS256')
        #     else:
        #         login = False
        #         id = id
        #         message = 'Please enter a valid username or password'
        #         status_code = 400
        #         status = 'error'
        #         logger.error(message)
        #         token = None
        #     final_dict = {'login': login, 'id': id, 'message': message, 'status': status, 'jwt': token}
        #     return Response(final_dict, status_code)
        except Exception as e:
            final_dict = {'login': False, 'id': None, 'message': str(e), 'status': 'error', 'jwt': None}
            return Response(final_dict, 400)


class UserUpdate(APIView):
    @staticmethod
    def put(request):
        '''
        update user
        :param request:
        :return: Response as json
        '''
        query_data = request.data
        token = request.headers['Authorization']
        # valid_data = jwt.decode(token, key='secret')
        id = 1
        # try:
        #     # model = UserProfile.objects.get(user_id=id)
        #     # model_serializer = UserSerializer(model, data=query_data)
        #     # if model_serializer.is_valid():
        #     #     model_serializer.save()
        #     #     id = id
        #     #     update = True
        #     #     status_code = 202
        #     else:
        #         print(model_serializer.errors)
        #         update = False
        #         id = None
        #         status_code = 400
        # except (TypeError, ValueError):
        #     import traceback
        #     traceback.print_exc()
        #     update = False
        #     id = None
        #     status_code = 400
        final_dict = {'update': True, 'id': id}
        return Response(final_dict, 201)


class UserDetails(APIView):
    def get(self, request):
        token = request.headers['Authorization']
        try:
            final_dict = {"name": 'Subham','pan_number' : 'Hidsp2311',
                              "email": 'email',
                              "mobile_num": 'mobile_num', "pic": 'picture'}
            final_response = {'data': final_dict, 'message': 'Profile is successfully fetched', 'status': 'success'}
            logger.info("Profile is successfully fetched")
            return Response(final_response, 200)
            logger.info("This is the API to retrieve user profile details")
            # valid_data = jwt.decode(token, key='secret')
            # print(valid_data)
            # final_data = UserProfile.objects.get(user_id=valid_data['id'])
            # print(final_data.first_name)
            # if final_data:
            #     final_dict = {"name": final_data.Name,'pan_number' : final_data.pan_number,
            #                   "email": final_data.email,
            #                   "mobile_num": final_data.mobile_num, "pic": final_data.picture}
            #     final_response = {'data': final_dict, 'message': 'Profile is successfully fetched', 'status': 'success'}
            #     logger.info("Profile is successfully fetched")
            #     return Response(final_response, 200)
            # else:
            #     final_response = {'data': {}, 'message': 'Error while fetching', 'status': 'Error'}
            #     logger.error("Error while fetching")
            #     return Response(final_response, 400)
        except Exception as e:
            final_response = {'data': {}, 'message': str(e), 'status': 'Error'}
            return Response(final_response, 400)


class UserDeactivate(APIView):

    def post(request):
        try:
            logger.info('This is the API for DeactivateAccount')
            token = request.headers['Authorization']
            valid_data = jwt.decode(token, key='secret')
            mail_id = UserProfile.objects.get(user_id=valid_data['id']).current_org_mail_id
            # mail_id = json_data.get('current_org_mail_id')
            if UserProfile.objects.filter(email=mail_id).exists():
                password = UserProfile.objects.get(email=mail_id).password
                old_password1 = UserProfile.objects.get(email=mail_id).old_password1
                UserProfile.objects.filter(email=mail_id).update(password="",
                                                                               update_time=datetime.datetime.utcnow())
                UserProfile.objects.filter(email=mail_id).update(old_password1=password,
                                                                               update_time=datetime.datetime.utcnow())
                UserProfile.objects.filter(email=mail_id).update(old_password2=old_password1,
                                                                               update_time=datetime.datetime.utcnow())
                final_dict = {'message': "Account disabled successfully"}
                logger.info("Account disabled successfully")
                logger.info("API executed successfully")
                return Response(final_dict, 200)
            else:
                final_dict = {'message': "User does not exist", 'status': 'error'}
                logger.error("User does not exist")
                return Response(final_dict, 400)
        except Exception as e:
            final_dict = {'message': str(e), 'status': 'error'}
            return Response(final_dict, 400)
