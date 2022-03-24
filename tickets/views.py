from django.shortcuts import render, redirect, get_object_or_404
from .models import TR, SPP, OrtrTR
from .forms import LinkForm, HotspotForm, PhoneForm, ItvForm, ShpdForm,\
    VolsForm, CopperForm, WirelessForm, CswForm, CksForm, PortVKForm, PortVMForm, VideoForm, LvsForm, LocalForm, SksForm,\
    UserRegistrationForm, UserLoginForm, OrtrForm, AuthForServiceForm, ContractForm, ListResourcesForm, \
    PassServForm, ChangeServForm, ChangeParamsForm, ListJobsForm, ChangeLogShpdForm, \
    TemplatesHiddenForm, TemplatesStaticForm, ListContractIdForm, ExtendServiceForm, PassTurnoffForm, SearchTicketsForm

import logging
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.core.paginator import Paginator


import datetime
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.forms import formset_factory

from .parsing import *
from .parsing import _parsing_vgws_by_node_name
from .parsing import _parsing_model_and_node_client_device_by_device_name
from .parsing import _get_chain_data
from .parsing import _counter_line_services

from .constructing_tr import *
from .constructing_tr import _separate_services_and_subnet_dhcp
from .constructing_tr import _titles

from .utils import *
from .utils import _replace_wda_wds
from .utils import _get_downlink
from .utils import _get_vgw_on_node
from .utils import _get_node_device
from .utils import _get_extra_node_device
from .utils import _get_uplink
from .utils import _get_extra_selected_ono
from .utils import _get_all_chain
from .utils import _tag_service_for_new_serv
from .utils import _readable

from django import template
register = template.Library()


logger = logging.getLogger(__name__)


def registration(request):
    """Данный метод отвечает за регистрацию пользователей в АРМ"""
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Вы успешно зарегистрировались')
            return redirect('ortr')
        else:
            messages.error(request, 'Ошибка регистрации')
    else:
        form = UserRegistrationForm()
    return render(request, 'tickets/register.html', {'form': form})


def user_login(request):
    """Данный метод отвечает за авторизацию пользователей в АРМ. Если авторизация запрашивается со страницы требующей
    авторизацию, то после авторизации происходит перенаправление на эту страницу. Если пользователь самостоятельно переходит
    на страницу авторизации, то перенаправление осуществляется в его Личное пространство"""
    if request.method == 'POST':
        form = UserLoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            next = request.GET.get('next', '/')
            if next == '/':
                return redirect('private_page')
            else:
                return redirect(request.GET['next'])
    else:
        form = UserLoginForm()
    return render(request, 'tickets/login.html', {'form': form})


def user_logout(request):
    """Данный метод отвечает за выход авторизованного пользователя"""
    logout(request)
    return redirect('login')


def change_password(request):
    """Данный метод отображает html страничку с формой для изменения пароля пользователя в АРМ"""
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Ваш пароль обновлен!')
            return redirect('change_password')
        else:
            messages.error(request, 'Ошибка')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'tickets/change_password.html', {
        'form': form
    })


@login_required(login_url='login/')
def private_page(request):
    """Данный метод в Личном пространстве пользователя отображает все задачи этого пользователя"""
    request = flush_session_key(request)
    spp_success = SPP.objects.filter(user=request.user).order_by('-created')
    paginator = Paginator(spp_success, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'tickets/private_page.html', {'page_obj': page_obj}) # 'spp_success': spp_success,


def login_for_service(request):
    """Данный метод перенаправляет на страницу Авторизация в ИС Холдинга. Метод используется для получения данных от пользователя
     для авторизации в ИС Холдинга. После получения данных, проверяет, что пароль не содержит русских символов и добавляет
      логин с паролем в redis(задает время хранения в параметре timeout) и перенаправляет на страницу, с которой пришел запрос"""
    if request.method == 'POST':
        authform = AuthForServiceForm(request.POST)
        if authform.is_valid():
            username = authform.cleaned_data['username']
            password = authform.cleaned_data['password']
            if re.search(r'[а-яА-Я]', password):
                messages.warning(request, 'Русская клавиатура')
                return redirect('login_for_service')
            else:
                user = User.objects.get(username=request.user.username)
                credent = dict()
                credent.update({'username': username})
                credent.update({'password': password})
                cache.set(user, credent, timeout=3600)
                if 'next' in request.GET:
                    return redirect(request.GET['next'])
                return redirect('ortr')
    else:
        authform = AuthForServiceForm()
    return render(request, 'tickets/login_is.html', {'form': authform})


def cache_check(func):
    """Данный декоратор осуществляет проверку, что пользователь авторизован в АРМ, и в redis есть его логин/пароль,
     если данных нет, то перенаправляет на страницу Авторизация в ИС Холдинга"""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login/?next=%s' % (request.path))
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        if credent == None:
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        return func(request, *args, **kwargs)
    return wrapper


@cache_check
def ortr(request):
    """Данный метод перенаправляет на страницу Новые заявки, которые находятся в пуле ОРТР/в работе.
        1. Получает данные от redis о логин/пароле
        2. Получает данные о всех заявках в пуле ОРТР с помощью метода in_work_ortr
        3. Получает данные о всех заявках которые уже находятся в БД(в работе)
        4. Удаляет из списка в пуле заявки, которые есть в работе
        5. Формирует итоговый список всех заявок в пуле/в работе"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    request = flush_session_key(request)
    search = in_work_ortr(username, password)
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        list_search = []
        if type(search[0]) != str:
            for i in search:
                list_search.append(i[0])
        spp_proc = SPP.objects.filter(process=True)
        list_spp_proc = []
        for i in spp_proc:
            list_spp_proc.append(i.ticket_k)
        spp_wait = SPP.objects.filter(wait=True)
        list_spp_wait = []
        return_from_wait = []
        for i in spp_wait:
            if i.ticket_k in list_search:
                list_spp_wait.append(i.ticket_k)
            else:
                i.wait = False
                i.save()
                return_from_wait.append(i.ticket_k)
        list_search_rem = []
        for i in list_spp_proc:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        for i in list_spp_wait:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        if search[0] == 'Empty list tickets':
            search = None
        else:
            search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
        if return_from_wait:
            messages.success(request, 'Заявка {} удалена из ожидания'.format(', '.join(return_from_wait)))
        return render(request, 'tickets/ortr.html', {'search': search, 'spp_process': spp_proc})


@cache_check
def commercial(request):
    """Данный метод перенаправляет на страницу Коммерческие заявки, которые находятся в работе ОРТР.
    1. Получает данные от redis о логин/пароле
    2. Получает данные о коммерческих заявках в пуле ОРТР с помощью метода in_work_ortr
    3. Получает данные о коммерческих заявках которые уже находятся в БД(в работе/в ожидании)
    4. Удаляет из списка в пуле заявки, которые есть в работе/в ожидании
    5. Формирует итоговый список задач в пуле и в работе"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    search = in_work_ortr(username, password)
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        list_search = []
        if type(search[0]) != str:
            search[:] = [x for x in search if 'ПТО' not in x[0]]
            for i in search:
                if 'ПТО' not in i[0]:
                    list_search.append(i[0])
        spp_process = SPP.objects.filter(Q(process=True) | Q(wait=True)).filter(type_ticket='Коммерческая')
        list_spp_process = []
        for i in spp_process:
            list_spp_process.append(i.ticket_k)
        list_search_rem = []
        for i in list_spp_process:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        if len(search) == 0 or search[0] == 'Empty list tickets':
            search = None
        else:
            search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
        spp_process = SPP.objects.filter(process=True).filter(type_ticket='Коммерческая')
        return render(request, 'tickets/ortr.html', {'search': search, 'com_search': True, 'spp_process': spp_process})


@cache_check
def pto(request):
    """Данный метод перенаправляет на страницу ПТО заявки, которые находятся в работе ОРТР.
        1. Получает данные от redis о логин/пароле
        2. Получает данные о ПТО заявках в пуле ОРТР с помощью метода in_work_ortr
        3. Получает данные о ПТО заявках которые уже находятся в БД(в работе/в ожидании)
        4. Удаляет из списка в пуле заявки, которые есть в работе/в ожидании
        5. Формирует итоговый список задач в пуле и в работе"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    search = in_work_ortr(username, password)
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        list_search = []
        if type(search[0]) != str:
            search[:] = [x for x in search if 'ПТО' in x[0]]
            for i in search:
                if 'ПТО' in i[0]:
                    list_search.append(i[0])
        spp_process = SPP.objects.filter(Q(process=True) | Q(wait=True)).filter(type_ticket='ПТО')
        list_spp_process = []
        for i in spp_process:
            list_spp_process.append(i.ticket_k)
        list_search_rem = []
        for i in list_spp_process:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        if len(search) == 0 or search[0] == 'Empty list tickets':
            search = None
        else:
            search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
        spp_process = SPP.objects.filter(process=True).filter(type_ticket='ПТО')
        return render(request, 'tickets/ortr.html', {'search': search, 'pto_search': True, 'spp_process': spp_process})


def wait(request):
    """Данный метод перенаправляет на страницу заявки в ожидании.
            1. Получает данные о всех заявках которые уже находятся в БД(в ожидании)
            2. Формирует итоговый список задач в ожидании"""
    spp_process = SPP.objects.filter(wait=True)
    return render(request, 'tickets/ortr.html', {'wait_search': True, 'spp_process': spp_process})


@cache_check
def all_com_pto_wait(request):
    """Данный метод перенаправляет на страницу Все заявки, которые находятся в пуле ОРТР/в работе/в ожидании.
        1. Получает данные от redis о логин/пароле
        2. Получает данные о всех заявках в пуле ОРТР с помощью метода in_work_ortr
        3. Получает данные о всех заявках которые уже находятся в БД(в работе/в ожидании)
        4. Удаляет из списка в пуле заявки, которые есть в работе/в ожидании
        5. Формирует итоговый список всех заявок в пуле/в работе/в ожидании"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    search = in_work_ortr(username, password)
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        list_search = []
        if type(search[0]) != str:
            for i in search:
                list_search.append(i[0])
        spp_proc_wait_all = SPP.objects.filter(Q(process=True) | Q(wait=True))
        list_spp_proc_wait_all = []
        for i in spp_proc_wait_all:
            list_spp_proc_wait_all.append(i.ticket_k)
        list_search_rem = []
        for i in list_spp_proc_wait_all:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        if search[0] == 'Empty list tickets':
            search = None
        else:
            search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
        spp_process = SPP.objects.filter(process=True)
        spp_wait = SPP.objects.filter(wait=True)
        return render(request, 'tickets/ortr.html', {'all_search': True, 'search': search, 'spp_process': spp_process, 'spp_wait': spp_wait})


@cache_check
def get_link_tr(request):
    """Данный метод открывает страницу Проектирование ТР
    1. Получает от пользователя ссылку на ТР
    2. Проверяет правильность ссылки
    3. Получает из ссылки параметры ТР dID, tID, trID
    4. Перенаправляет на метод project_tr"""
    if request.method == 'POST':
        linkform = LinkForm(request.POST)
        if linkform.is_valid():
            spplink = linkform.cleaned_data['spplink']
            manlink = spplink
            regex_link = 'dem_tr\/dem_begin\.php\?dID=(\d+)&tID=(\d+)&trID=(\d+)'
            match_link = re.search(regex_link, spplink)
            if match_link:
                dID = match_link.group(1)
                tID = match_link.group(2)
                trID = match_link.group(3)
                request.session['manlink'] = manlink
                return redirect('project_tr', dID, tID, trID)
            else:
                messages.warning(request, 'Неверная ссылка')
                return redirect('get_link_tr')
    else:
        list_session_keys = []
        for key in request.session.keys():
            if key.startswith('_'):
                pass
            else:
                list_session_keys.append(key)
        for key in list_session_keys:
            del request.session[key]
        linkform = LinkForm()
    return render(request, 'tickets/inputtr.html', {'linkform': linkform})


def project_tr(request, dID, tID, trID):
    """Данный метод на входе получает параметры ссылки ТР в СПП, с помощью метода parse_tr получает данные из ТР в СПП,
    формирует последовательность url'ов по которым необходимо пройти для получения данных от пользователя и
    перенаправляет на первый из них. Используется для новой точки подключения."""
    spplink = 'https://sss.corp.itmh.ru/dem_tr/dem_begin.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    data_sss = parse_tr(username, password, spplink)
    if data_sss[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    elif data_sss[2] == 'Не выбран':
        return redirect('tr_view', dID, tID, trID)
    else:
        services_plus_desc = data_sss[0]
        counter_line_services = data_sss[1]
        pps = data_sss[2]
        turnoff = data_sss[3]
        sreda = data_sss[4]
        tochka = data_sss[5]
        hotspot_points = data_sss[6]
        oattr = data_sss[7]
        address = data_sss[8]
        client = data_sss[9]
        manager = data_sss[10]
        technolog = data_sss[11]
        task_otpm = data_sss[12]
        request.session['services_plus_desc'] = services_plus_desc
        request.session['counter_line_services'] = counter_line_services
        request.session['pps'] = pps
        request.session['turnoff'] = turnoff
        request.session['sreda'] = sreda
        request.session['tochka'] = tochka
        request.session['address'] = address
        request.session['oattr'] = oattr
        request.session['spplink'] = spplink
        request.session['client'] = client
        request.session['manager'] = manager
        request.session['technolog'] = technolog
        request.session['task_otpm'] = task_otpm
        request.session['tID'] = tID
        request.session['dID'] = dID
        request.session['trID'] = trID
        tag_service, hotspot_users, premium_plus = _tag_service_for_new_serv(services_plus_desc)
        tag_service.insert(0, {'sppdata': None})
        request.session['hotspot_points'] = hotspot_points
        request.session['hotspot_users'] = hotspot_users
        request.session['premium_plus'] = premium_plus
        if counter_line_services == 0:
            tag_service.append({'data': None})
        else:
            if sreda == '1':
                tag_service.append({'copper': None})
            elif sreda == '2' or sreda == '4':
                tag_service.append({'vols': None})
            elif sreda == '3':
                tag_service.append({'wireless': None})
        request.session['tag_service'] = tag_service
        return redirect(next(iter(tag_service[0])))



def sppdata(request):
    """Данный метод отображает html-страничку с данными о ТР для новой точки подключения"""
    services_plus_desc = request.session['services_plus_desc']
    client = request.session['client']
    manager = request.session['manager']
    technolog = request.session['technolog']
    task_otpm = request.session['task_otpm']
    address = request.session['address']
    turnoff = request.session['turnoff']
    tag_service = request.session['tag_service']
    tag_service.pop(0)
    next_link = next(iter(tag_service[0]))
    request.session['tag_service'] = tag_service
    context = {
        'services_plus_desc': services_plus_desc,
        'client': client,
        'manager': manager,
        'technolog': technolog,
        'task_otpm': task_otpm,
        'address': address,
        'next_link': next_link,
        'turnoff': turnoff
    }
    return render(request, 'tickets/sppdata.html', context)



@cache_check
def copper(request):
    """Данный метод отображает html-страничку с параметрами для медной линии связи"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    if request.method == 'POST':
        copperform = CopperForm(request.POST)
        if copperform.is_valid():
            correct_sreda = copperform.cleaned_data['correct_sreda']
            sreda = request.session['sreda']
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if correct_sreda == sreda:
                logic_csw = copperform.cleaned_data['logic_csw']
                logic_replace_csw = copperform.cleaned_data['logic_replace_csw']
                logic_change_gi_csw = copperform.cleaned_data['logic_change_gi_csw']
                logic_change_csw = copperform.cleaned_data['logic_change_csw']
                port = copperform.cleaned_data['port']
                kad = copperform.cleaned_data['kad']
                tag_service = request.session['tag_service']
                request.session['logic_csw'] = logic_csw
                request.session['logic_replace_csw'] = logic_replace_csw
                request.session['logic_change_csw'] = logic_change_csw
                request.session['logic_change_gi_csw'] = logic_change_gi_csw
                request.session['port'] = port
                request.session['kad'] = kad
                try:
                    type_pass = request.session['type_pass']
                except KeyError:
                    pass
                else:
                    selected_ono = request.session['selected_ono']
                    if 'Перенос, СПД' in type_pass:
                        type_passage = request.session['type_passage']
                        if type_passage == 'Перенос сервиса в новую точку' or (type_passage == 'Перевод на гигабит' and not any([logic_change_csw, logic_change_gi_csw])):
                            selected_service = selected_ono[0][-3]
                            service_shpd = ['DA', 'BB', 'inet', 'Inet', '128 -', '53 -', '34 -', '33 -', '32 -', '54 -', '57 -', '60 -', '62 -', '64 -', '68 -', '92 -', '96 -', '101 -', '105 -', '125 -', '107 -', '109 -', '483 -']
                            if any(serv in selected_service for serv in service_shpd):
                                tag_service.append({'change_log_shpd': None})
                                request.session['subnet_for_change_log_shpd'] = selected_ono[0][-4]
                        else:
                            readable_services = request.session['readable_services']
                            _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services, 'Новая подсеть /32')
                            if service_shpd_change:
                                request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                                tag_service.append({'change_log_shpd': None})
                    elif 'Организация/Изменение, СПД' in type_pass and not 'Перенос, СПД' in type_pass and logic_csw == True:
                        readable_services = request.session['readable_services']
                        _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services,
                                                                                    'Новая подсеть /32')
                        request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                        tag_service.append({'change_log_shpd': None})

                if logic_csw == True:
                    tag_service.append({'csw': None})
                    return redirect(next(iter(tag_service[0])))
                elif logic_replace_csw == True and logic_change_gi_csw == True or logic_replace_csw == True:
                    tag_service.append({'csw': None})
                    return redirect(next(iter(tag_service[0])))
                elif logic_change_csw == True and logic_change_gi_csw == True or logic_change_csw == True:
                    if type_pass:
                        if 'Организация/Изменение, СПД' in type_pass and 'Перенос, СПД' not in type_pass:
                            tag_service.insert(0, {'pass_serv': None})
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                elif logic_change_gi_csw == True:
                    if type_pass:
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                else:
                    tag_service.append({'data': None})
                    return redirect(next(iter(tag_service[0])))
            else:
                if correct_sreda == '3':
                    tag_service.insert(0, {'wireless': None})
                elif correct_sreda == '2' or correct_sreda == '4':
                    tag_service.insert(0, {'vols': None})
                request.session['sreda'] = correct_sreda
                return redirect(next(iter(tag_service[0])))
    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        services_plus_desc = request.session['services_plus_desc']
        sreda = request.session['sreda']
        oattr = request.session['oattr']
        try:
            type_pass = request.session['type_pass']
        except KeyError:
            type_pass = None

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')
        list_switches, switches_name = add_portconfig_to_list_swiches(list_switches, username, password)
        request.session['list_switches'] = list_switches
        copperform = CopperForm(initial={'correct_sreda': '1', 'kad': switches_name, 'port': 'свободный'})

        context = {
            'pps': pps,
            'oattr': oattr,
            'list_switches': list_switches,
            'sreda': sreda,
            'copperform': copperform
        }
        return render(request, 'tickets/env.html', context)


@cache_check
def vols(request):
    """Данный метод отображает html-страничку с параметрами для ВОЛС"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    if request.method == 'POST':
        volsform = VolsForm(request.POST)

        if volsform.is_valid():
            correct_sreda = volsform.cleaned_data['correct_sreda']
            sreda = request.session['sreda']
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if correct_sreda == sreda:
                device_client = volsform.cleaned_data['device_client']
                device_pps = volsform.cleaned_data['device_pps']
                logic_csw = volsform.cleaned_data['logic_csw']
                logic_replace_csw = volsform.cleaned_data['logic_replace_csw']
                logic_change_csw = volsform.cleaned_data['logic_change_csw']
                logic_change_gi_csw = volsform.cleaned_data['logic_change_gi_csw']
                port = volsform.cleaned_data['port']
                kad = volsform.cleaned_data['kad']
                speed_port = volsform.cleaned_data['speed_port']
                request.session['device_pps'] = device_pps
                request.session['logic_csw'] = logic_csw
                request.session['logic_replace_csw'] = logic_replace_csw
                request.session['logic_change_gi_csw'] = logic_change_gi_csw
                request.session['logic_change_csw'] = logic_change_csw
                request.session['port'] = port
                request.session['speed_port'] = speed_port
                request.session['kad'] = kad
                try:
                    ppr = volsform.cleaned_data['ppr']
                except KeyError:
                    ppr = None
                request.session['ppr'] = ppr

                try:
                    type_pass = request.session['type_pass']
                except KeyError:
                    pass
                else:
                    selected_ono = request.session['selected_ono']
                    if 'Перенос, СПД' in type_pass:
                        type_passage = request.session['type_passage']
                        if type_passage == 'Перенос сервиса в новую точку' or (type_passage == 'Перевод на гигабит' and not any([logic_change_csw, logic_change_gi_csw])):
                            selected_ono = request.session['selected_ono']
                            selected_service = selected_ono[0][-3]
                            service_shpd = ['DA', 'BB', 'inet', 'Inet', '128 -', '53 -', '34 -', '33 -', '32 -', '54 -',
                                            '57 -', '60 -', '62 -', '64 -', '68 -', '92 -', '96 -', '101 -', '105 -',
                                            '125 -', '107 -', '109 -', '483 -']
                            if any(serv in selected_service for serv in service_shpd):
                                tag_service.append({'change_log_shpd': None})
                                request.session['subnet_for_change_log_shpd'] = selected_ono[0][-4]
                        else:
                            readable_services = request.session['readable_services']
                            _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services, 'Новая подсеть /32')
                            if service_shpd_change:
                                request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                                tag_service.append({'change_log_shpd': None})
                    elif 'Организация/Изменение, СПД' in type_pass and not 'Перенос, СПД' in type_pass and logic_csw == True:
                        readable_services = request.session['readable_services']
                        _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services,
                                                                                    'Новая подсеть /32')
                        request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                        tag_service.append({'change_log_shpd': None})

                if logic_csw == True:
                    device_client = device_client.replace('клиентское оборудование', 'клиентский коммутатор')
                    request.session['device_client'] = device_client
                    tag_service.append({'csw': None})
                    return redirect(next(iter(tag_service[0])))
                elif logic_change_csw == True and logic_change_gi_csw == True or logic_change_csw == True:
                    device_client = device_client.replace(' в клиентское оборудование', '')
                    request.session['device_client'] = device_client
                    if type_pass:
                        if 'Организация/Изменение, СПД' in type_pass and 'Перенос, СПД' not in type_pass:
                            tag_service.insert(0, {'pass_serv': None})
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                elif logic_replace_csw == True and logic_change_gi_csw == True or logic_replace_csw == True:
                    device_client = device_client.replace(' в клиентское оборудование', '')
                    request.session['device_client'] = device_client
                    if type_pass:
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                elif logic_change_gi_csw == True:
                    device_client = device_client.replace(' в клиентское оборудование', '')
                    request.session['device_client'] = device_client
                    if type_pass:
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                else:
                    request.session['device_client'] = device_client
                    #return redirect('data')
                    tag_service.append({'data': None})
                    return redirect(next(iter(tag_service[0])))
            else:
                if correct_sreda == '1':
                    tag_service.insert(0, {'copper': None})
                elif correct_sreda == '3':
                    tag_service.insert(0, {'wireless': None})
                elif correct_sreda == '2':
                    tag_service.insert(0, {'vols': None})
                elif correct_sreda == '4':
                    tag_service.insert(0, {'vols': None})
                request.session['sreda'] = correct_sreda
                return redirect(next(iter(tag_service[0])))
    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        services_plus_desc = request.session['services_plus_desc']
        turnoff = request.session['turnoff']
        sreda = request.session['sreda']
        oattr = request.session['oattr']
        spplink = request.session['spplink']
        regex_link = 'dem_tr\/dem_begin\.php\?dID=(\d+)&tID=(\d+)&trID=(\d+)'
        match_link = re.search(regex_link, spplink)
        dID = match_link.group(1)
        tID = match_link.group(2)
        trID = match_link.group(3)
        try:
            type_pass = request.session['type_pass']
        except KeyError:
            type_pass = None

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')
        list_switches, switches_name = add_portconfig_to_list_swiches(list_switches, username, password)
        request.session['list_switches'] = list_switches

        if sreda == '2':
            volsform = VolsForm(
                    initial={'correct_sreda': '2',
                            'device_pps': 'конвертер 1310 нм, выставить на конвертере режим работы Auto',
                             'device_client': 'конвертер 1550 нм, выставить на конвертере режим работы Auto',
                             'kad': switches_name,
                             'speed_port': 'Auto',
                             'port': 'свободный'})
        elif sreda == '4':
            volsform = VolsForm(
                        initial={'correct_sreda': '4',
                                'device_pps': 'оптический передатчик SFP WDM, до 3 км, 1310 нм',
                                 'device_client': 'конвертер 1550 нм, выставить на конвертере режим работы Auto',
                                 'kad': switches_name,
                                 'speed_port': '100FD'})
        else:
            volsform = VolsForm()

        context = {
            'pps': pps,
            'oattr': oattr,
            'list_switches': list_switches,
            'sreda': sreda,
            'turnoff': turnoff,
            'dID': dID,
            'tID': tID,
            'trID': trID,
            'volsform': volsform
        }
        return render(request, 'tickets/env.html', context)


@cache_check
def wireless(request):
    """Данный метод отображает html-страничку с параметрами для беспроводной среды"""
    if request.method == 'POST':
        wirelessform = WirelessForm(request.POST)

        if wirelessform.is_valid():
            correct_sreda = wirelessform.cleaned_data['correct_sreda']
            sreda = request.session['sreda']
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if correct_sreda == sreda:
                access_point = wirelessform.cleaned_data['access_point']
                port = wirelessform.cleaned_data['port']
                kad = wirelessform.cleaned_data['kad']
                logic_csw = wirelessform.cleaned_data['logic_csw']
                logic_replace_csw = wirelessform.cleaned_data['logic_replace_csw']
                logic_change_csw = wirelessform.cleaned_data['logic_change_csw']
                logic_change_gi_csw = wirelessform.cleaned_data['logic_change_gi_csw']
                try:
                    ppr = wirelessform.cleaned_data['ppr']
                except KeyError:
                    ppr = None
                request.session['ppr'] = ppr
                request.session['access_point'] = access_point
                request.session['port'] = port
                request.session['kad'] = kad
                request.session['logic_csw'] = logic_csw
                request.session['logic_replace_csw'] = logic_replace_csw
                request.session['logic_change_gi_csw'] = logic_change_gi_csw
                request.session['logic_change_csw'] = logic_change_csw
                try:
                    type_pass = request.session['type_pass']
                except KeyError:
                    pass
                else:
                    if 'Перенос, СПД' in type_pass:
                        type_passage = request.session['type_passage']
                        if type_passage == 'Перенос сервиса в новую точку' or (type_passage == 'Перевод на гигабит' and not any([logic_change_csw, logic_change_gi_csw])):
                            selected_ono = request.session['selected_ono']
                            selected_service = selected_ono[0][-3]
                            service_shpd = ['DA', 'BB', 'inet', 'Inet', '128 -', '53 -', '34 -', '33 -', '32 -', '54 -',
                                            '57 -', '60 -', '62 -', '64 -', '68 -', '92 -', '96 -', '101 -', '105 -',
                                            '125 -', '107 -', '109 -', '483 -']
                            if any(serv in selected_service for serv in service_shpd):
                                tag_service.append({'change_log_shpd': None})
                                request.session['subnet_for_change_log_shpd'] = selected_ono[0][-4]
                        else:
                            readable_services = request.session['readable_services']
                            _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services, 'Новая подсеть /32')
                            if service_shpd_change:
                                request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                                tag_service.append({'change_log_shpd': None})

                    elif 'Организация/Изменение, СПД' in type_pass and not 'Перенос, СПД' in type_pass and logic_csw == True:
                        readable_services = request.session['readable_services']
                        _, service_shpd_change = _separate_services_and_subnet_dhcp(readable_services,
                                                                                    'Новая подсеть /32')
                        request.session['subnet_for_change_log_shpd'] = ' '.join(service_shpd_change)
                        tag_service.append({'change_log_shpd': None})

                if logic_csw == True:
                    tag_service.append({'csw': None})
                    return redirect(next(iter(tag_service[0])))
                elif logic_change_csw == True or logic_change_gi_csw == True:
                    if type_pass:
                        if 'Организация/Изменение, СПД' in type_pass and 'Перенос, СПД' not in type_pass:
                            tag_service.insert(0, {'pass_serv': None})
                        tag_service.append({'csw': None})
                        return redirect(next(iter(tag_service[0])))
                else:
                    tag_service.append({'data': None})
                    return redirect(next(iter(tag_service[0])))
            else:
                if correct_sreda == '1':
                    tag_service.insert(0, {'copper': None})
                elif correct_sreda == '2' or correct_sreda == '4':
                    tag_service.insert(0, {'vols': None})
                request.session['sreda'] = correct_sreda
                return redirect(next(iter(tag_service[0])))
    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        turnoff = request.session['turnoff']
        sreda = request.session['sreda']
        oattr = request.session['oattr']

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')
        list_switches, switches_name = add_portconfig_to_list_swiches(list_switches, username, password)
        request.session['list_switches'] = list_switches
        wirelessform = WirelessForm(initial={'correct_sreda': '3', 'kad': switches_name, 'port': 'свободный'})
        context = {
            'pps': pps,
            'oattr': oattr,
            'list_switches': list_switches,
            'sreda': sreda,
            'turnoff': turnoff,
            'wirelessform': wirelessform
        }
        return render(request, 'tickets/env.html', context)


@cache_check
def vgws(request):
    """Данный метод отображает html-страничку со списком тел. шлюзов"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    pps = request.session['pps']
    vgws = _parsing_vgws_by_node_name(username, password, NodeName=pps)
    return render(request, 'tickets/vgws.html', {'vgws': vgws, 'pps': pps})


def csw(request):
    """Данный метод отображает форму с параметрами КК"""
    if request.method == 'POST':
        cswform = CswForm(request.POST)
        if cswform.is_valid():
            model_csw = cswform.cleaned_data['model_csw']
            port_csw = cswform.cleaned_data['port_csw']
            logic_csw_1000 = cswform.cleaned_data['logic_csw_1000']
            exist_speed_csw = cswform.cleaned_data['exist_speed_csw']
            type_install_csw = cswform.cleaned_data['type_install_csw']
            exist_sreda_csw = cswform.cleaned_data['exist_sreda_csw']
            request.session['model_csw'] = model_csw
            request.session['port_csw'] = port_csw
            request.session['logic_csw_1000'] = logic_csw_1000
            request.session['exist_speed_csw'] = exist_speed_csw
            request.session['type_install_csw'] = type_install_csw
            request.session['exist_sreda_csw'] = exist_sreda_csw
            if not type_install_csw:
                request.session['logic_csw'] = True
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            tag_service.append({'data': None})
            return redirect(next(iter(tag_service[0])))
    else:
        sreda = request.session['sreda']
        try:
            request.session['type_pass']
        except KeyError:
            add_serv_install = False
            new_install = True
            logic_change_gi_csw = None
            logic_replace_csw = None
            logic_change_csw = False
        else:
            if request.session.get('logic_change_gi_csw'):
                logic_change_gi_csw = request.session.get('logic_change_gi_csw')
                add_serv_install = False
                new_install = False
                if request.session.get('logic_replace_csw'):
                    logic_replace_csw = True
                else:
                    logic_replace_csw = None
                if request.session.get('logic_change_csw'):
                    logic_change_csw = True
                else:
                    logic_change_csw = False
            elif request.session.get('logic_csw'):
                add_serv_install = request.session.get('logic_csw')
                new_install = False
                logic_change_gi_csw = False
                logic_replace_csw = None
                logic_change_csw = False
            elif request.session.get('logic_replace_csw'):
                logic_replace_csw = request.session.get('logic_replace_csw')
                add_serv_install = False
                new_install = False
                logic_change_gi_csw = False
                logic_change_csw = False
            elif request.session.get('logic_change_csw'):
                logic_change_csw = request.session.get('logic_replace_csw')
                add_serv_install = False
                new_install = False
                logic_change_gi_csw = False
                logic_replace_csw = False

        if sreda == '2' or sreda == '4':
            cswform = CswForm(initial={'model_csw': 'D-Link DGS-1100-06/ME', 'port_csw': '6'})
        else:
            cswform = CswForm(initial={'model_csw': 'D-Link DGS-1100-06/ME', 'port_csw': '5'})

        context = {
            'cswform': cswform,
            'add_serv_install': add_serv_install,
            'new_install': new_install,
            'logic_change_gi_csw': logic_change_gi_csw,
            'logic_replace_csw': logic_replace_csw,
            'logic_change_csw': logic_change_csw
        }
        return render(request, 'tickets/csw.html', context)

import json

def data(request):
    """Данный метод определяет какой требуется тип ТР(перенос, организация доп. услуг, организация нов. точки и т.д),
     вызывает соответствующие методы для формирования готового ТР, добавления даты, описания существующего подключения,
      поля Требуется и перенаправляет на метод отображающий готовое ТР"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    templates = ckb_parse(username, password)
    request.session['templates'] = templates
    value_vars = {}
    for key, value in request.session.items():
        value_vars.update({key: value})

    ticket_tr_id = request.session['ticket_tr_id']
    ticket_tr = TR.objects.get(id=ticket_tr_id)
    type_ticket = ticket_tr.ticket_k.type_ticket
    value_vars.update({'type_ticket': type_ticket})
    # with open('data.json', 'w', encoding='utf-8') as f:
    #     json.dump(value_vars, f, ensure_ascii=False, indent=4)
    readable_services = value_vars.get('readable_services')

    if value_vars.get('type_pass') and 'Перенос, СПД' in value_vars.get('type_pass'):
        if (value_vars.get('logic_csw') and 'Организация/Изменение, СПД' in value_vars.get('type_pass')) or (value_vars.get('logic_change_csw') and 'Организация/Изменение, СПД' in value_vars.get('type_pass')):
            pass
        elif value_vars.get('logic_csw'):
            counter_line_services = value_vars.get('counter_exist_line')
            value_vars.update({'counter_line_services': counter_line_services})
            result_services, result_services_ots, value_vars = passage_services_with_install_csw(value_vars)
        elif value_vars.get('logic_change_csw') or value_vars.get('logic_change_gi_csw'):
            counter_line_services = 0 # суть в том что организуем линии в блоке переноса КК типа порт в порт, т.к. если меняется лог подк, то орг линий не треб
            value_vars.update({'counter_line_services': counter_line_services})
            result_services, result_services_ots, value_vars = passage_services_with_passage_csw(value_vars)
        elif value_vars.get('type_passage') == 'Перевод на гигабит' and value_vars.get('change_log') == 'Порт и КАД не меняется':
            result_services, result_services_ots, value_vars = extend_service(value_vars)
        elif value_vars.get('type_passage') == 'Перенос логического подключения' and value_vars.get('change_log') == 'Порт и КАД не меняется':
            result_services, result_services_ots, value_vars = passage_track(value_vars)
        elif value_vars.get('type_passage') == 'Перенос точки подключения' and value_vars.get('change_log') == 'Порт и КАД не меняется' and value_vars.get('selected_ono')[0][-2].startswith('CSW'):
            result_services, result_services_ots, value_vars = passage_csw_no_install(value_vars)
        else:
            counter_line_services = value_vars.get('counter_line_services')
            if value_vars.get('type_passage') == 'Перенос сервиса в новую точку' or value_vars.get('type_passage') == 'Перевод на гигабит':
                value_vars.update({'counter_line_services': 1})
            else:
                value_vars.update({'counter_line_services': value_vars.get('counter_exist_line')})
            result_services, result_services_ots, value_vars = passage_services(value_vars)
            value_vars.update({'counter_line_services': counter_line_services})
            value_vars.update({'result_services': result_services})
            value_vars.update({'result_services_ots': result_services_ots})

    if value_vars.get('type_pass') and 'Организация/Изменение, СПД' in value_vars.get('type_pass'):
        if value_vars.get('logic_csw'):
            counter_line_services = value_vars.get('counter_line_services') + value_vars.get('counter_exist_line')
            value_vars.update(({'services_plus_desc': value_vars.get('new_job_services')}))
            value_vars.update({'counter_line_services': counter_line_services})
            result_services, result_services_ots, value_vars = extra_services_with_install_csw(value_vars)
        elif value_vars.get('logic_replace_csw') and value_vars.get('logic_change_gi_csw') or value_vars.get('logic_replace_csw'):
            value_vars.update(({'services_plus_desc': value_vars.get('new_job_services')}))
            result_services, result_services_ots, value_vars = extra_services_with_replace_csw(value_vars)
        elif value_vars.get('logic_change_gi_csw') or value_vars.get('logic_change_csw'):
            value_vars.update(({'services_plus_desc': value_vars.get('new_job_services')}))
            result_services, result_services_ots, value_vars = extra_services_with_passage_csw(value_vars)
        else:
            value_vars.update(({'services_plus_desc': value_vars.get('new_job_services')}))
            result_services, result_services_ots, value_vars = client_new(value_vars)
        value_vars.update({'result_services': result_services})
        value_vars.update({'result_services_ots': result_services_ots})
        if value_vars.get('type_passage') and value_vars.get('type_passage') == 'Перевод на гигабит':
            result_services, result_services_ots, value_vars = extend_service(value_vars)
            value_vars.update({'result_services': result_services})
            value_vars.update({'result_services_ots': result_services_ots})

    if value_vars.get('type_pass') and 'Изменение, не СПД' in value_vars.get('type_pass'):
        result_services, result_services_ots, value_vars = change_services(value_vars)

    if value_vars.get('not_required'):
        result_services = 'Решение ОУЗП СПД не требуется'
        result_services_ots = None

    if not value_vars.get('type_pass') and not value_vars.get('not_required'):
        result_services, result_services_ots, value_vars = client_new(value_vars)

    userlastname = None
    if request.user.is_authenticated:
        userlastname = request.user.last_name
    now = datetime.datetime.now()
    now = now.strftime("%d.%m.%Y")
    need = get_need(value_vars)
    if value_vars.get('type_pass'):
        titles = _titles(result_services, result_services_ots)
        titles = ''.join(titles)
        request.session['titles'] = titles
        result_services = '\n\n\n'.join(result_services)
        result_services = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + value_vars.get('head') +'\n\n'+ need + '\n\n' + titles + '\n' + result_services
    elif value_vars.get('not_required'):
        result_services = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + result_services
    else:
        titles = _titles(result_services, result_services_ots)
        titles = ''.join(titles)
        request.session['titles'] = titles
        result_services = '\n\n\n'.join(result_services)
        result_services = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + titles + '\n' + result_services
    counter_str_ortr = result_services.count('\n')

    if result_services_ots == None:
        counter_str_ots = 1
    else:
        result_services_ots = '\n\n\n'.join(result_services_ots)
        result_services_ots = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + result_services_ots
        counter_str_ots = result_services_ots.count('\n')

    request.session['kad'] = value_vars.get('kad') if value_vars.get('kad') else 'Не требуется'
    request.session['pps'] = value_vars.get('pps') if value_vars.get('pps') else 'Не требуется'
    request.session['result_services'] = result_services
    request.session['counter_str_ortr'] = counter_str_ortr
    request.session['result_services_ots'] = result_services_ots
    request.session['counter_str_ots'] = counter_str_ots
    try:
        manlink = request.session['manlink']
    except KeyError:
        manlink = None

    if manlink:
        return redirect('unsaved_data')
    else:
        return redirect('saved_data')


def unsaved_data(request):
    """Данный метод отображает нередактируемую html-страничку готового ТР"""
    services_plus_desc = request.session['services_plus_desc']
    oattr = request.session['oattr']
    titles = request.session['titles']
    result_services = request.session['result_services']
    counter_str_ortr = request.session['counter_str_ortr']
    counter_str_ots = request.session['counter_str_ots']
    result_services_ots = request.session['result_services_ots']
    try:
        list_switches = request.session['list_switches']
    except KeyError:
        list_switches = None
    now = datetime.datetime.now()
    context = {
        'services_plus_desc': services_plus_desc,
        'oattr': oattr,
        'titles': titles,
        'result_services': result_services,
        'result_services_ots': result_services_ots,
        'now': now,
        'list_switches': list_switches,
        'counter_str_ortr': counter_str_ortr,
        'counter_str_ots': counter_str_ots
    }
    return render(request, 'tickets/data.html', context)


def saved_data(request):
    """Данный метод отображает редактируемую html-страничку готового ТР"""
    if request.method == 'POST':
        ortrform = OrtrForm(request.POST)
        if ortrform.is_valid():
            services_plus_desc = request.session['services_plus_desc']
            oattr = request.session['oattr']
            # counter_str_ortr = request.session['counter_str_ortr']
            # counter_str_ots = request.session['counter_str_ots']
            result_services_ots = request.session['result_services_ots']
            try:
                list_switches = request.session['list_switches']
            except KeyError:
                list_switches = None
            now = datetime.datetime.now()

            ortr_field = ortrform.cleaned_data['ortr_field']
            ots_field = ortrform.cleaned_data['ots_field']
            pps = ortrform.cleaned_data['pps']
            kad = ortrform.cleaned_data['kad']
            ticket_tr_id = request.session['ticket_tr_id']
            ticket_tr = TR.objects.get(id=ticket_tr_id)
            ticket_k = ticket_tr.ticket_k
            ticket_tr.pps = pps
            ticket_tr.kad = kad
            ticket_tr.save()
            ortr_id = request.session['ortr_id']
            ortr = OrtrTR.objects.get(id=ortr_id)
            ortr.ortr = ortr_field
            ortr.ots = ots_field
            ortr.save()
            counter_str_ortr = ortr.ortr.count('\n')
            if ortr.ots:
                counter_str_ots = ortr.ots.count('\n')
            else:
                counter_str_ots = 1

            context = {
                'ticket_k': ticket_k,
                'services_plus_desc': services_plus_desc,
                'oattr': oattr,
                'result_services_ots': result_services_ots,
                'list_switches': list_switches,
                'counter_str_ortr': counter_str_ortr,
                'counter_str_ots': counter_str_ots,
                'ortrform': ortrform
            }
            return render(request, 'tickets/saved_data.html', context)

    else:
        services_plus_desc = request.session['services_plus_desc']
        oattr = request.session['oattr']
        kad = request.session['kad']
        if kad == 'Не требуется':
            pps = 'Не требуется'
        else:
            pps = request.session['pps']
        result_services = request.session['result_services']
        counter_str_ortr = request.session['counter_str_ortr']
        counter_str_ots = request.session['counter_str_ots']
        result_services_ots = request.session['result_services_ots']
        try:
            list_switches = request.session['list_switches']
        except KeyError:
            list_switches = None
        ticket_tr_id = request.session['ticket_tr_id']
        ticket_tr = TR.objects.get(id=ticket_tr_id)
        ticket_k = ticket_tr.ticket_k
        ticket_tr.kad = kad
        ticket_tr.pps = pps
        ticket_tr.save()
        if ticket_tr.ortrtr_set.all():
            ortr = ticket_tr.ortrtr_set.all()[0]
        else:
            ortr = OrtrTR()
        ortr.ticket_tr = ticket_tr
        ortr.ortr = result_services
        ortr.ots = result_services_ots
        ortr.save()
        request.session['ortr_id'] = ortr.id
        ortrform = OrtrForm(initial={'ortr_field': ortr.ortr, 'ots_field': ortr.ots, 'pps': pps, 'kad': kad})

        context = {
            'ticket_k': ticket_k,
            'services_plus_desc': services_plus_desc,
            'oattr': oattr,
            'result_services_ots': result_services_ots,
            'list_switches': list_switches,
            'counter_str_ortr': counter_str_ortr,
            'counter_str_ots': counter_str_ots,
            'ortrform': ortrform

        }
        return render(request, 'tickets/saved_data.html', context)


def edit_tr(request, dID, ticket_spp_id, trID):
    """Данный метод отображает html-страничку для редактирования ТР существующего в БД"""
    if request.method == 'POST':
        ortrform = OrtrForm(request.POST)
        if ortrform.is_valid():
            ortr_field = ortrform.cleaned_data['ortr_field']
            ots_field = ortrform.cleaned_data['ots_field']
            pps = ortrform.cleaned_data['pps']
            kad = ortrform.cleaned_data['kad']
            ticket_tr_id = request.session['ticket_tr_id']
            ticket_tr = TR.objects.get(id=ticket_tr_id)
            ticket_tr.pps = pps
            ticket_tr.kad = kad
            ticket_tr.save()
            ortr_id = request.session['ortr_id']
            ortr = OrtrTR.objects.get(id=ortr_id)
            ortr.ortr = ortr_field
            ortr.ots = ots_field
            ortr.save()
            counter_str_ortr = ortr.ortr.count('\n')
            if ortr.ots:
                counter_str_ots = ortr.ots.count('\n')
            else:
                counter_str_ots = 1

            context = {
                'services_plus_desc': ticket_tr.services,
                'oattr': ticket_tr.oattr,
                'counter_str_ortr': counter_str_ortr,
                'counter_str_ots': counter_str_ots,
                'ortrform': ortrform,
                'ticket_spp_id': ticket_spp_id,
                'dID': dID,
                'ticket_tr': ticket_tr
            }
            return render(request, 'tickets/edit_tr.html', context)
    else:
        ticket_spp_id = request.session['ticket_spp_id']
        dID = request.session['dID']
        ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)
        ticket_tr = ticket_spp.children.filter(ticket_tr=trID)[0]
        request.session['ticket_tr_id'] = ticket_tr.id
        ortr = ticket_tr.ortrtr_set.all()[0]
        request.session['ortr_id'] = ortr.id
        counter_str_ortr = ortr.ortr.count('\n')
        if ortr.ots:
            counter_str_ots = ortr.ots.count('\n')
        else:
            counter_str_ots = 1
        ortrform = OrtrForm(initial={'ortr_field': ortr.ortr, 'ots_field': ortr.ots, 'pps': ticket_tr.pps, 'kad': ticket_tr.kad})

        context = {
            'services_plus_desc': ticket_tr.services,
            'oattr': ticket_tr.oattr,
            'counter_str_ortr': counter_str_ortr,
            'counter_str_ots': counter_str_ots,
            'ortrform': ortrform,
            'ticket_spp_id': ticket_spp_id,
            'dID': dID,
            'ticket_tr': ticket_tr
        }
        return render(request, 'tickets/edit_tr.html', context)


@cache_check
def manually_tr(request, dID, tID, trID):
    """Данный метод отображает html-страничку для написания ТР вручную"""
    if request.method == 'POST':
        ortrform = OrtrForm(request.POST)
        if ortrform.is_valid():
            ticket_spp_id = request.session['ticket_spp_id']
            ortr_field = ortrform.cleaned_data['ortr_field']
            ots_field = ortrform.cleaned_data['ots_field']
            pps = ortrform.cleaned_data['pps']
            kad = ortrform.cleaned_data['kad']
            ticket_tr_id = request.session['ticket_tr_id']
            ticket_tr = TR.objects.get(id=ticket_tr_id)
            ticket_tr.pps = pps
            ticket_tr.kad = kad
            ticket_tr.save()
            ortr_id = request.session['ortr_id']
            ortr = OrtrTR.objects.get(id=ortr_id)
            ortr.ortr = ortr_field
            ortr.ots = ots_field
            ortr.save()
            counter_str_ortr = ortr.ortr.count('\n')
            if ortr.ots:
                counter_str_ots = ortr.ots.count('\n')
            else:
                counter_str_ots = 1

            context = {
                'services_plus_desc': ticket_tr.services,
                'oattr': ticket_tr.oattr,
                'counter_str_ortr': counter_str_ortr,
                'counter_str_ots': counter_str_ots,
                'ortrform': ortrform,
                'ticket_spp_id': ticket_spp_id,
                'dID': dID,
                'ticket_tr': ticket_tr
            }
            return render(request, 'tickets/edit_tr.html', context)
    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        tr_params = for_tr_view(username, password, dID, tID, trID)
        if tr_params.get('Access denied') == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        else:
            spplink = 'https://sss.corp.itmh.ru/dem_tr/dem_begin.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)
            request.session['spplink'] = spplink
            ticket_spp_id = request.session['ticket_spp_id']
            ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)
            if ticket_spp.children.filter(ticket_tr=trID):
                return redirect('edit_tr', dID, ticket_spp_id, trID)
            ticket_tr = TR()
            ticket_tr.ticket_k = ticket_spp
            ticket_tr.ticket_tr = trID
            ticket_tr.pps = tr_params['Узел подключения клиента']
            ticket_tr.turnoff = False if tr_params['Отключение'] == 'Нет' else True
            ticket_tr.info_tr = tr_params['Информация для разработки ТР']
            ticket_tr.services = tr_params['Перечень требуемых услуг']
            ticket_tr.connection_point = tr_params['Точка подключения']
            ticket_tr.oattr = tr_params['Решение ОТПМ']
            ticket_tr.vID = tr_params['vID']
            ticket_tr.save()
            request.session['ticket_tr_id'] = ticket_tr.id
            ortr = OrtrTR()
            ortr.ticket_tr = ticket_tr
            ortr.save()
            request.session['ortr_id'] = ortr.id
            for service in ticket_tr.services:
                if 'Телефон' in service:
                    counter_str_ots = 10
                else:
                    counter_str_ots = 1
            ortrform = OrtrForm()

            context = {
                'services_plus_desc': ticket_tr.services,
                'oattr': ticket_tr.oattr,
                'counter_str_ortr': 10,
                'counter_str_ots': counter_str_ots,
                'ortrform': ortrform,
                'ticket_spp_id': ticket_spp_id,
                'dID': dID,
                'ticket_tr': trID
            }
            return render(request, 'tickets/edit_tr.html', context)


@cache_check
def send_to_spp(request):
    """Данный метод заполняет поля блока ОРТР в СПП готовым ТР"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    spplink = request.session['spplink']
    url = spplink.replace('dem_begin', 'dem_point')
    req_check = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
    if req_check.status_code == 200:
        ticket_tr_id = request.session['ticket_tr_id']
        ticket_tr = TR.objects.get(id=ticket_tr_id)
        trOTO_AV = ticket_tr.pps
        trOTO_Comm = ticket_tr.kad
        vID = ticket_tr.vID
        if ticket_tr.ortrtr_set.all():
            ortr = ticket_tr.ortrtr_set.all()[0]
            trOTO_Resolution = ortr.ortr
            trOTS_Resolution = ortr.ots
        data = {'trOTO_Resolution': trOTO_Resolution, 'trOTS_Resolution': trOTS_Resolution, 'action': 'saveVariant',
                'trOTO_AV': trOTO_AV, 'trOTO_Comm': trOTO_Comm, 'vID': vID}
        req = requests.post(url, verify=False, auth=HTTPBasicAuth(username, password), data=data)
        return redirect(spplink)
    else:
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response


def hotspot(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Хот-спот"""
    if request.method == 'POST':
        hotspotform = HotspotForm(request.POST)

        if hotspotform.is_valid():
            hotspot_points = hotspotform.cleaned_data['hotspot_points']
            hotspot_users = hotspotform.cleaned_data['hotspot_users']
            exist_hotspot_client = hotspotform.cleaned_data['exist_hotspot_client']
            services_plus_desc = request.session['services_plus_desc']
            counter_line_services = request.session['counter_line_services']
            if hotspot_points:
                for index_service in range(len(services_plus_desc)):
                    if 'HotSpot' in services_plus_desc[index_service]:
                        for i in range(int(hotspot_points)):
                            services_plus_desc[index_service] += '|'
                counter_line_services += hotspot_points-1
            request.session['counter_line_services'] = counter_line_services
            request.session['services_plus_desc'] = services_plus_desc
            request.session['hotspot_points'] = str(hotspot_points)
            request.session['hotspot_users'] = str(hotspot_users)
            request.session['exist_hotspot_client'] = exist_hotspot_client
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))

    else:
        hotspot_points = request.session['hotspot_points']
        hotspot_users = request.session['hotspot_users']
        premium_plus = request.session['premium_plus']
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'HotSpot' in service:
                service_hotspot = service
                break
        hotspotform = HotspotForm(initial={'hotspot_points': hotspot_points, 'hotspot_users': hotspot_users})
        context = {
            'premium_plus': premium_plus,
            'hotspotform': hotspotform,
            'service_hotspot': service_hotspot
        }
        return render(request, 'tickets/hotspot.html', context)

def phone(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Телефония"""
    if request.method == 'POST':
        phoneform = PhoneForm(request.POST)
        if phoneform.is_valid():
            type_phone = phoneform.cleaned_data['type_phone']
            vgw = phoneform.cleaned_data['vgw']
            channel_vgw = phoneform.cleaned_data['channel_vgw']
            ports_vgw = phoneform.cleaned_data['ports_vgw']
            type_ip_trunk = phoneform.cleaned_data['type_ip_trunk']
            form_exist_vgw_model = phoneform.cleaned_data['form_exist_vgw_model']
            form_exist_vgw_name = phoneform.cleaned_data['form_exist_vgw_name']
            form_exist_vgw_port = phoneform.cleaned_data['form_exist_vgw_port']
            services_plus_desc = request.session['services_plus_desc']
            new_job_services = request.session.get('new_job_services')
            phone_in_pass = request.session.get('phone_in_pass')
            tag_service = request.session['tag_service']
            if phone_in_pass and phone_in_pass not in services_plus_desc:
                services_plus_desc.append(phone_in_pass)
            for index_service in range(len(services_plus_desc)):
                if 'Телефон' in services_plus_desc[index_service]:
                    if type_phone == 'ak' or type_phone == 'st':
                        if new_job_services:
                            for ind in range(len(new_job_services)):
                                if new_job_services[ind] == services_plus_desc[index_service]:
                                    new_job_services[ind] += '|'
                        services_plus_desc[index_service] += '|'
                        if phone_in_pass:
                            phone_in_pass += '|'
                            request.session['phone_in_pass'] = phone_in_pass
                        else:
                            try:
                                counter_line_services = request.session['counter_line_services']
                            except KeyError:
                                counter_line_services = 0
                            if type_phone == 'st':
                                request.session['type_ip_trunk'] = type_ip_trunk
                                if type_ip_trunk == 'trunk':
                                    request.session['counter_line_services'] = 1
                                elif type_ip_trunk == 'access':
                                    counter_line_services += 1
                                    request.session['counter_line_services'] = counter_line_services
                            if type_phone == 'ak':
                                counter_line_services += 1
                                request.session['counter_line_services'] = counter_line_services
                        sreda = request.session['sreda']
                        if sreda == '2' or sreda == '4':
                            if {'vols': None} in tag_service:
                                pass
                            else:
                                tag_service.insert(1, {'vols': None})
                        elif sreda == '3':
                            if {'wireless': None} in tag_service:
                                pass
                            else:
                                tag_service.insert(1, {'wireless': None})
                        elif sreda == '1':
                            if {'copper': None} in tag_service:
                                pass
                            else:
                                tag_service.insert(1, {'copper': None})
                        if {'data': None} in tag_service:
                            tag_service.remove({'data': None})
                    elif type_phone == 'ap':
                        if new_job_services:
                            for ind in range(len(new_job_services)):
                                if new_job_services[ind] == services_plus_desc[index_service]:
                                    new_job_services[ind] += '/'
                        if phone_in_pass:
                            phone_in_pass += '/'
                            request.session['phone_in_pass'] = phone_in_pass
                        services_plus_desc[index_service] += '/'
                        if {'copper': None} in tag_service:
                            pass
                        else:
                            tag_service.insert(1, {'copper': None})
                    elif type_phone == 'ab':
                        if new_job_services:
                            for ind in range(len(new_job_services)):
                                if new_job_services[ind] == services_plus_desc[index_service]:
                                    new_job_services[ind] += '\\'
                        if phone_in_pass:
                            phone_in_pass += '\\'
                            request.session['phone_in_pass'] = phone_in_pass
                        services_plus_desc[index_service] += '\\'
                        request.session['form_exist_vgw_model'] = form_exist_vgw_model
                        request.session['form_exist_vgw_name'] = form_exist_vgw_name
                        request.session['form_exist_vgw_port'] = form_exist_vgw_port
            if phone_in_pass and phone_in_pass not in new_job_services:
                services_plus_desc = [x for x in services_plus_desc if not x.startswith('Телефон')]
            request.session['services_plus_desc'] = services_plus_desc
            request.session['vgw'] = vgw
            request.session['channel_vgw'] = channel_vgw
            request.session['ports_vgw'] = ports_vgw
            request.session['type_phone'] = type_phone
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        oattr = request.session['oattr']
        if request.session.get('phone_in_pass'):
            reg_ports_vgw = 'Нет данных'
            reg_channel_vgw = 'Нет данных'
            service_vgw = request.session.get('phone_in_pass')
            vats = False
        else:
            for service in services_plus_desc:
                if 'Телефон' in service:
                    regex_ports_vgw = ['(\d+)-порт', '(\d+) порт', '(\d+)порт']
                    for regex in regex_ports_vgw:
                        match_ports_vgw = re.search(regex, service)
                        if match_ports_vgw:
                            reg_ports_vgw = match_ports_vgw.group(1)
                        else:
                            reg_ports_vgw = 'Нет данных'
                        break
                    regex_channel_vgw = ['(\d+)-канал', '(\d+) канал', '(\d+)канал']
                    for regex in regex_channel_vgw:
                        match_channel_vgw = re.search(regex, service)
                        if match_channel_vgw:
                            reg_channel_vgw = match_channel_vgw.group(1)
                        else:
                            reg_channel_vgw = 'Нет данных'
                        break
                    service_vgw = service
                    if 'ватс' in service.lower():
                        vats = True
                    else:
                        vats = False
                    break
        phoneform = PhoneForm(initial={
                                'type_phone': 's', 'vgw': 'Не требуется', 'channel_vgw': reg_channel_vgw, 'ports_vgw': reg_ports_vgw
                            })
        context = {
            'service_vgw': service_vgw,
            'vats': vats,
            'oattr': oattr,
            'phoneform': phoneform
        }
        return render(request, 'tickets/phone.html', context)

def local(request):
    """Данный метод отображает html-страничку c формой для выбора СКС/ЛВС"""
    if request.method == 'POST':
        localform = LocalForm(request.POST)
        if localform.is_valid():
            local_type = localform.cleaned_data['local_type']
            local_ports = localform.cleaned_data['local_ports']
            request.session['local_type'] = local_type
            request.session['local_ports'] = str(local_ports)
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            if local_type == 'СКС':
                return redirect('sks')
            elif local_type == 'ЛВС':
                return redirect('lvs')
            else:
                new_job_services = request.session.get('new_job_services')
                if new_job_services:
                    new_job_services[:] = [x for x in new_job_services if not x.startswith('ЛВС')]
                services_plus_desc = request.session['services_plus_desc']
                services_plus_desc[:] = [x for x in services_plus_desc if not x.startswith('ЛВС')]
                request.session['services_plus_desc'] = services_plus_desc
                return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'ЛВС' in service:
                service_lvs = service
                request.session['service_lvs'] = service_lvs
                break
        localform = LocalForm()
        context = {
            'service_lvs': service_lvs,
            'localform': localform
        }
        return render(request, 'tickets/local.html', context)


def sks(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге СКС"""
    if request.method == 'POST':
        sksform = SksForm(request.POST)
        if sksform.is_valid():
            sks_poe = sksform.cleaned_data['sks_poe']
            sks_router = sksform.cleaned_data['sks_router']
            request.session['sks_poe'] = sks_poe
            request.session['sks_router'] = sks_router
            tag_service = request.session['tag_service']
            return redirect(next(iter(tag_service[0])))
    else:
        service_lvs = request.session['service_lvs']
        sksform = SksForm()
        context = {
            'service_lvs': service_lvs,
            'sksform': sksform
        }
        return render(request, 'tickets/sks.html', context)


def lvs(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге ЛВС"""
    if request.method == 'POST':
        lvsform = LvsForm(request.POST)
        if lvsform.is_valid():
            lvs_busy = lvsform.cleaned_data['lvs_busy']
            lvs_switch = lvsform.cleaned_data['lvs_switch']
            request.session['lvs_busy'] = lvs_busy
            request.session['lvs_switch'] = lvs_switch
            tag_service = request.session['tag_service']
            return redirect(next(iter(tag_service[0])))
    else:
        service_lvs = request.session['service_lvs']
        lvsform = LvsForm()
        context = {
            'service_lvs': service_lvs,
            'lvsform': lvsform
        }
        return render(request, 'tickets/lvs.html', context)


def itv(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Вебург.ТВ"""
    if request.method == 'POST':
        itvform = ItvForm(request.POST)
        if itvform.is_valid():
            type_itv = itvform.cleaned_data['type_itv']
            cnt_itv = itvform.cleaned_data['cnt_itv']
            router_itv = itvform.cleaned_data['router_itv']
            services_plus_desc = request.session['services_plus_desc']
            tag_service = request.session['tag_service']
            try:
                new_job_services = request.session['new_job_services']
            except KeyError:
                new_job_services = None
                if type_itv == 'novlexist':
                    messages.warning(request, 'Нельзя выбрать действующее ШПД, проектирование в нов. точке')
                    return redirect(next(iter(tag_service[0])))
            for index_service in range(len(services_plus_desc)):
                if 'iTV' in services_plus_desc[index_service]:
                    if type_itv == 'vl':
                        if new_job_services:
                            for ind in range(len(new_job_services)):
                                if new_job_services[ind] == services_plus_desc[index_service]:
                                    new_job_services[ind] += '|'
                        services_plus_desc[index_service] += '|'
                        counter_line_services = request.session['counter_line_services']
                        counter_line_services += 1
                        request.session['counter_line_services'] = counter_line_services
                        sreda = request.session['sreda']
                        if sreda == '2' or sreda == '4':
                            if {'vols': None} not in tag_service:
                                tag_service.insert(1, {'vols': None})
                        elif sreda == '3':
                            if 'wireless' not in tag_service:
                                tag_service.insert(1, {'wireless': None})
                        elif sreda == '1':
                            if 'copper' not in tag_service:
                                tag_service.insert(1, {'copper': None})
                        if {'data': None} in tag_service:
                            tag_service.remove({'data': None})
            request.session['new_job_services'] = new_job_services
            request.session['services_plus_desc'] = services_plus_desc
            request.session['type_itv'] = type_itv
            request.session['cnt_itv'] = cnt_itv
            request.session['router_itv'] = router_itv
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'iTV' in service:
                service_itv = service
                break
        itvform = ItvForm(initial={'type_itv': 'novl'})
        return render(request, 'tickets/itv.html', {'itvform': itvform, 'service_itv': service_itv})


def cks(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге ЦКС"""
    if request.method == 'POST':
        cksform = CksForm(request.POST)
        if cksform.is_valid():
            pointA = cksform.cleaned_data['pointA']
            pointB = cksform.cleaned_data['pointB']
            policer_cks = cksform.cleaned_data['policer_cks']
            type_cks = cksform.cleaned_data['type_cks']
            exist_service = cksform.cleaned_data['exist_service']
            if type_cks and type_cks == 'trunk':
                request.session['counter_line_services'] = 1
            try:
                all_cks_in_tr = request.session['all_cks_in_tr']
            except KeyError:
                all_cks_in_tr = dict()
            tag_service = request.session['tag_service']
            service = tag_service[0]['cks']
            all_cks_in_tr.update({service:{'pointA': pointA, 'pointB': pointB, 'policer_cks': policer_cks, 'type_cks': type_cks, 'exist_service': exist_service}})
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            request.session['all_cks_in_tr'] = all_cks_in_tr
            return redirect(next(iter(tag_service[0])))
    else:
        tag_service = request.session['tag_service']
        service = tag_service[0]['cks']
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        types_change_service = request.session.get('types_change_service')
        trunk_turnoff_on, trunk_turnoff_off = trunk_turnoff_shpd_cks_vk_vm(service, types_change_service)
        try:
            tochka = request.session['tochka']
            list_cks = match_cks(tochka, username, password)
        except KeyError:
            list_cks = request.session['cks_points']
        if list_cks[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        else:
            if len(list_cks) == 2:
                pointA = list_cks[0]
                pointB = list_cks[1]
                cksform = CksForm(initial={'pointA': pointA, 'pointB': pointB})
                return render(request, 'tickets/cks.html', {
                    'cksform': cksform,
                    'services_cks': service,
                    'trunk_turnoff_on': trunk_turnoff_on,
                    'trunk_turnoff_off': trunk_turnoff_off
                })
            else:
                cksform = CksForm()
                return render(request, 'tickets/cks.html', {
                    'cksform': cksform,
                    'list_strok': list_cks,
                    'services_cks': service,
                    'trunk_turnoff_on': trunk_turnoff_on,
                    'trunk_turnoff_off': trunk_turnoff_off
                })


def shpd(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге ШПД"""
    if request.method == 'POST':
        shpdform = ShpdForm(request.POST)
        if shpdform.is_valid():
            router_shpd = shpdform.cleaned_data['router']
            type_shpd = shpdform.cleaned_data['type_shpd']
            exist_service = shpdform.cleaned_data['exist_service']
            if type_shpd == 'trunk':
                request.session['counter_line_services'] = 1
            try:
                all_shpd_in_tr = request.session['all_shpd_in_tr']
            except KeyError:
                all_shpd_in_tr = dict()
            tag_service = request.session['tag_service']
            service = tag_service[0]['shpd']
            all_shpd_in_tr.update({service:{'router_shpd': router_shpd, 'type_shpd': type_shpd, 'exist_service': exist_service}})
            request.session['all_shpd_in_tr'] = all_shpd_in_tr
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        types_change_service = request.session.get('types_change_service')
        tag_service = request.session['tag_service']
        service = tag_service[0]['shpd']
        trunk_turnoff_on, trunk_turnoff_off = trunk_turnoff_shpd_cks_vk_vm(service, types_change_service)
        shpdform = ShpdForm(initial={'shpd': 'access'})
        context = {
            'shpdform': shpdform,
            'services_shpd': service,
            'trunk_turnoff_on': trunk_turnoff_on,
            'trunk_turnoff_off': trunk_turnoff_off
        }
        return render(request, 'tickets/shpd.html', context)


def portvk(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Порт ВЛС"""
    if request.method == 'POST':
        portvkform = PortVKForm(request.POST)
        if portvkform.is_valid():
            new_vk = portvkform.cleaned_data['new_vk']
            exist_vk = '"{}"'.format(portvkform.cleaned_data['exist_vk'])
            policer_vk = portvkform.cleaned_data['policer_vk']
            type_portvk = portvkform.cleaned_data['type_portvk']
            exist_service = portvkform.cleaned_data['exist_service']
            if type_portvk == 'trunk':
                request.session['counter_line_services'] = 1
            try:
                all_portvk_in_tr = request.session['all_portvk_in_tr']
            except KeyError:
                all_portvk_in_tr = dict()
            tag_service = request.session['tag_service']
            service = tag_service[0]['portvk']
            all_portvk_in_tr.update({service:{'new_vk': new_vk, 'exist_vk': exist_vk, 'policer_vk': policer_vk, 'type_portvk': type_portvk, 'exist_service': exist_service}})
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            request.session['all_portvk_in_tr'] = all_portvk_in_tr
            return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        services_vk = []
        for service in services_plus_desc:
            if 'Порт ВЛС' in service:
                services_vk.append(service)
        types_change_service = request.session.get('types_change_service')
        trunk_turnoff_on, trunk_turnoff_off = trunk_turnoff_shpd_cks_vk_vm(service, types_change_service)
        portvkform = PortVKForm()
        context = {'portvkform': portvkform,
                   'services_vk': services_vk,
                   'trunk_turnoff_on': trunk_turnoff_on,
                   'trunk_turnoff_off': trunk_turnoff_off
                   }
        return render(request, 'tickets/portvk.html', context)


def portvm(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Порт ВМ"""
    if request.method == 'POST':
        portvmform = PortVMForm(request.POST)
        if portvmform.is_valid():
            new_vm = portvmform.cleaned_data['new_vm']
            exist_vm = '"{}"'.format(portvmform.cleaned_data['exist_vm'])
            policer_vm = portvmform.cleaned_data['policer_vm']
            vm_inet = portvmform.cleaned_data['vm_inet']
            type_portvm = portvmform.cleaned_data['type_portvm']
            exist_service_vm = portvmform.cleaned_data['exist_service_vm']
            if type_portvm == 'trunk':
                request.session['counter_line_services'] = 1
            request.session['policer_vm'] = policer_vm
            request.session['new_vm'] = new_vm
            request.session['exist_vm'] = exist_vm
            request.session['vm_inet'] = vm_inet
            request.session['type_portvm'] = type_portvm
            request.session['exist_service_vm'] = exist_service_vm
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        services_vm = []
        for service in services_plus_desc:
            if 'Порт ВМ' in service:
                services_vm.append(service)
        types_change_service = request.session.get('types_change_service')
        trunk_turnoff_on, trunk_turnoff_off = trunk_turnoff_shpd_cks_vk_vm(service, types_change_service)
        portvmform = PortVMForm()
        context = {'portvmform': portvmform,
                   'services_vm': services_vm,
                   'trunk_turnoff_on': trunk_turnoff_on,
                   'trunk_turnoff_off': trunk_turnoff_off
                   }
        return render(request, 'tickets/portvm.html', context)


def video(request):
    """Данный метод отображает html-страничку c формой для заполнения данных по услуге Видеонаблюдение"""
    if request.method == 'POST':
        videoform = VideoForm(request.POST)
        if videoform.is_valid():
            camera_number = videoform.cleaned_data['camera_number']
            camera_model = videoform.cleaned_data['camera_model']
            voice = videoform.cleaned_data['voice']
            deep_archive = videoform.cleaned_data['deep_archive']
            camera_place_one = videoform.cleaned_data['camera_place_one']
            camera_place_two = videoform.cleaned_data['camera_place_two']
            request.session['camera_number'] = str(camera_number)
            request.session['camera_model'] = camera_model
            request.session['voice'] = voice
            request.session['deep_archive'] = deep_archive
            request.session['camera_place_one'] = camera_place_one
            request.session['camera_place_two'] = camera_place_two
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'Видеонаблюдение' in service:
                service_video = service
                request.session['service_video'] = service_video
                break
        task_otpm = request.session['task_otpm']
        videoform = VideoForm()
        context = {
            'service_video': service_video,
            'videoform': videoform,
            'task_otpm': task_otpm
        }
        return render(request, 'tickets/video.html', context)


@cache_check
def get_resources(request):
    """Данный метод получает от пользователя номер договора. с помощью метода get_contract_id получает ID договора.
     С помощью метода get_contract_resources получает ресурсы с контракта. Отправляет пользователя на страницу, где
    отображаются эти ресурсы.
    Если несколько договоров удовлетворяющих поиску - перенаправляет на страницу выбора конкретного договора."""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    if request.method == 'POST':
        contractform = ContractForm(request.POST)
        if contractform.is_valid():
            contract = contractform.cleaned_data['contract']
            contract_id = get_contract_id(username, password, contract)
            if isinstance(contract_id, list):
                request.session['contract_id'] = contract_id
                request.session['contract'] = contract
                return redirect('contract_id_formset')
            else:
                if contract_id == 'Такого договора не найдено':
                    messages.warning(request, 'Договора не найдено')
                    return redirect('get_resources')
                ono = get_contract_resources(username, password, contract_id)
                phone_address = check_contract_phone_exist(username, password, contract_id)
                if phone_address:
                    request.session['phone_address'] = phone_address
                request.session['ono'] = ono
                request.session['contract'] = contract
                return redirect('resources_formset')
    else:
        contractform = ContractForm()
    return render(request, 'tickets/contract.html', {'contractform': contractform})


@cache_check
def add_spp(request, dID):
    """Данный метод принимает параметр заявки СПП, проверяет наличие данных в БД с таким параметром. Если в БД есть
     ТР с таким параметром, то помечает данную заявку как новую версию, если нет, то помечает как версию 1.
     Получает данные с помощью метода for_spp_view и добавляет в БД. Перенаправляет на метод spp_view_save"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    try:
        current_spp = SPP.objects.filter(dID=dID).latest('created')
    except ObjectDoesNotExist:
        spp_params = for_spp_view(username, password, dID)
        if spp_params.get('Access denied') == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        else:
            version = 1
            ticket_spp = SPP()
            ticket_spp.dID = dID
            ticket_spp.ticket_k = spp_params['Заявка К']
            ticket_spp.client = spp_params['Клиент']
            ticket_spp.type_ticket = spp_params['Тип заявки']
            ticket_spp.manager = spp_params['Менеджер']
            ticket_spp.technolog = spp_params['Технолог']
            ticket_spp.task_otpm = spp_params['Задача в ОТПМ']
            ticket_spp.des_tr = spp_params['Состав Заявки ТР']
            ticket_spp.services = spp_params['Перечень требуемых услуг']
            ticket_spp.comment = spp_params['Примечание']
            ticket_spp.version = version
            ticket_spp.process = True
            user = User.objects.get(username=request.user.username)
            ticket_spp.user = user
            ticket_spp.save()
            return redirect('spp_view_save', dID, ticket_spp.id)
    else:
        if current_spp.process == True:
            messages.warning(request, '{} уже взял в работу'.format(current_spp.user.last_name))
            return redirect('ortr')

        else:
            spp_params = for_spp_view(username, password, dID)
            if spp_params.get('Access denied') == 'Access denied':
                messages.warning(request, 'Нет доступа в ИС Холдинга')
                response = redirect('login_for_service')
                response['Location'] += '?next={}'.format(request.path)
                return response
            else:
                exist_dID = len(SPP.objects.filter(dID=dID))
                version = exist_dID + 1
                ticket_spp = SPP()
                ticket_spp.dID = dID
                ticket_spp.ticket_k = spp_params['Заявка К']
                ticket_spp.client = spp_params['Клиент']
                ticket_spp.type_ticket = spp_params['Тип заявки']
                ticket_spp.manager = spp_params['Менеджер']
                ticket_spp.technolog = spp_params['Технолог']
                ticket_spp.task_otpm = spp_params['Задача в ОТПМ']
                ticket_spp.des_tr = spp_params['Состав Заявки ТР']
                ticket_spp.services = spp_params['Перечень требуемых услуг']
                ticket_spp.comment = spp_params['Примечание']
                ticket_spp.version = version
                ticket_spp.process = True
                user = User.objects.get(username=request.user.username)
                ticket_spp.user = user
                ticket_spp.save()
                #request.session['ticket_spp_id'] = ticket_spp.id
                return redirect('spp_view_save', dID, ticket_spp.id)

def remove_spp_process(request, ticket_spp_id):
    """Данный метод удаляет заявку из обрабатываемых заявок"""
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.process = False
    current_ticket_spp.save()
    messages.success(request, 'Работа по заявке {} завершена'.format(current_ticket_spp.ticket_k))
    return redirect('ortr')


def remove_spp_wait(request, ticket_spp_id):
    """Данный метод удаляет заявку из заявок в ожидании"""
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.wait = False
    current_ticket_spp.save()
    messages.success(request, 'Заявка {} возвращена из ожидания'.format(current_ticket_spp.ticket_k))
    return redirect('ortr')

def add_spp_wait(request, ticket_spp_id):
    """Данный метод добавляет заявку в заявки в ожидании"""
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.wait = True
    current_ticket_spp.was_waiting = True
    current_ticket_spp.process = False
    current_ticket_spp.save()
    messages.success(request, 'Заявка {} перемещена в ожидание'.format(current_ticket_spp.ticket_k))
    return redirect('wait')


def spp_view_save(request, dID, ticket_spp_id):
    """Данный метод отображает html-страничку с данными заявки взятой в работу или обработанной. Данные о заявке
     получает из БД"""
    request.session['ticket_spp_id'] = ticket_spp_id
    request.session['dID'] = dID
    current_ticket_spp = get_object_or_404(SPP, dID=dID, id=ticket_spp_id)
    return render(request, 'tickets/spp_view_save.html', {'current_ticket_spp': current_ticket_spp})

@cache_check
def spp_view(request, dID):
    """Данный метод отображает html-страничку с данными заявки находящейся в пуле ОРТР. Данные о заявке получает
    с помощью метода for_spp_view из СПП."""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    spp_params = for_spp_view(username, password, dID)
    if spp_params.get('Access denied') == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        return render(request, 'tickets/spp_view.html', {'spp_params': spp_params})


@cache_check
def add_tr(request, dID, tID, trID):
    """Данный метод получает данные о ТР из СПП и добавляет ТР новой точки подключения в АРМ"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    tr_params = for_tr_view(username, password, dID, tID, trID)
    if tr_params.get('Access denied') == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        ticket_spp_id = request.session['ticket_spp_id']
        ticket_tr_id = add_tr_to_db(dID, trID, tr_params, ticket_spp_id)
        request.session['ticket_tr_id'] = ticket_tr_id
        return redirect('project_tr', dID, tID, trID)


def add_tr_to_db(dID, trID, tr_params, ticket_spp_id):
    """Данный метод получает ID заявки СПП, ID ТР, параметры полученные с распарсенной страницы ТР, ID заявки в АРМ.
    создает ТР в АРМ и добавляет в нее данные. Возвращает ID ТР в АРМ"""
    ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)
    if ticket_spp.children.filter(ticket_tr=trID):
        ticket_tr = ticket_spp.children.filter(ticket_tr=trID)[0]
    else:
        ticket_tr = TR()
    ticket_tr.ticket_k = ticket_spp
    ticket_tr.ticket_tr = trID
    ticket_tr.pps = tr_params['Узел подключения клиента']
    ticket_tr.turnoff = False if tr_params['Отключение'] == 'Нет' else True
    ticket_tr.info_tr = tr_params['Информация для разработки ТР']
    ticket_tr.services = tr_params['Перечень требуемых услуг']
    ticket_tr.connection_point = tr_params['Точка подключения']
    ticket_tr.oattr = tr_params['Решение ОТПМ']
    ticket_tr.vID = tr_params['vID']
    ticket_tr.save()
    ticket_tr_id = ticket_tr.id
    return ticket_tr_id


def tr_view_save(request, dID, ticket_spp_id, trID):
    """Данный метод отображает html-страничку c данными обработанного ТР из БД АРМ"""
    ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)
    #get_object_or_404 не используется т.к. 'RelatedManager' object has no attribute 'get_object_or_404'
    try:
        ticket_tr = ticket_spp.children.get(ticket_tr=trID)
    except TR.DoesNotExist:
        raise Http404("ТР не создавалось")

    try:
        ortr = ticket_tr.ortrtr_set.all()[0]
    except IndexError:
        raise Http404("Блока ОРТР нет")
    return render(request, 'tickets/tr_view_save.html', {'ticket_tr': ticket_tr, 'ortr': ortr})


@cache_check
def tr_view(request, dID, tID, trID):
    """Данный метод отображает html-страничку c данными ТР из СПП"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    ticket_tr = for_tr_view(username, password, dID, tID, trID)
    if ticket_tr.get('Access denied') == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        return render(request, 'tickets/tr_view.html', {'ticket_tr': ticket_tr})


def get_title_tr(request):
    """Данный метод очищает сессию и перенаправляет на get_resources"""
    flush_session_key(request)
    return redirect('get_resources')


def title_tr(request):
    """Данный метод отображает html-страничку с шапкой ТР"""
    head = request.session['head']
    return render(request, 'tickets/title_tr.html', {'head': head})


@cache_check
def contract_id_formset(request):
    """Данный метод отображает форму, в которой пользователь выбирает 1 из договоров наиболее удовлетворяющих
     поисковому запросу договора, с помощью метода get_contract_resources получает ресурсы с этого договора
      и перенаправляет на форму для выбора ресурса для работ.
      Если выбрано более одного или ни одного договора возвращает эту же форму повторно."""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    contract_id = request.session['contract_id']
    ListContractIdFormSet = formset_factory(ListContractIdForm, extra=len(contract_id))
    if request.method == 'POST':
        formset = ListContractIdFormSet(request.POST)
        if formset.is_valid():
            data = formset.cleaned_data
            selected_contract_id = []
            unselected_contract_id = []
            selected = zip(contract_id, data)
            for contract_id, data in selected:
                if bool(data):
                    selected_contract_id.append(contract_id.get('id'))
            if selected_contract_id:
                if len(selected_contract_id) > 1:
                    messages.warning(request, 'Было выбрано более 1 ресурса')
                    return redirect('contract_id_formset')
                else:
                    ono = get_contract_resources(username, password, selected_contract_id[0])
                    if ono:
                        phone_address = check_contract_phone_exist(username, password, selected_contract_id[0])
                        if phone_address:
                            request.session['phone_address'] = phone_address
                        request.session['ono'] = ono
                        return redirect('resources_formset')
                    else:
                        messages.warning(request, 'На контракте нет ресурсов')
                        return redirect('contract_id_formset')
            else:
                messages.warning(request, 'Контракты не выбраны')
                return redirect('contract_id_formset')
    else:
        formset = ListContractIdFormSet()
        context = {
            'contract_id': contract_id,
            'formset': formset,
        }
        return render(request, 'tickets/contract_id_formset.html', context)



def resources_formset(request):
    """Данный метод получает спискок ресурсов с выбранного договора. Формирует форму, в которой пользователь выбирает
     только 1 ресурс, который будет участвовать в ТР. По коммутатору этого ресурса метод добавляет все ресурсы с данным
      коммутатором в итоговый список. Если выбрано более одного или ни одного ресурса возвращает эту же форму повторно.
      По точке подключения(город, улица) проверяет наличие телефонии на договоре. Отправляет пользователя на страницу
      формирования заголовка."""
    ono = request.session['ono']
    try:
        phone_address = request.session['phone_address']
    except KeyError:
        phone_address = None
    ListResourcesFormSet = formset_factory(ListResourcesForm, extra=len(ono))
    if request.method == 'POST':
        formset = ListResourcesFormSet(request.POST)
        if formset.is_valid():
            data = formset.cleaned_data
            selected_ono = []
            unselected_ono = []
            selected = zip(ono, data)
            for ono, data in selected:
                if bool(data):
                    selected_ono.append(ono)
                else:
                    unselected_ono.append(ono)
            if selected_ono:
                if len(selected_ono) > 1:
                    messages.warning(request, 'Было выбрано более 1 ресурса')
                    return redirect('resources_formset')
                else:
                    for i in unselected_ono:
                        if selected_ono[0][-2] == i[-2]:
                            selected_ono.append(i)
                    if phone_address:
                        if any(phone_addr in selected_ono[0][3] for phone_addr in phone_address):
                            phone_exist = True
                        else:
                            phone_exist = False
                    else:
                        phone_exist = False
                    request.session['phone_exist'] = phone_exist
                    request.session['selected_ono'] = selected_ono
                    return redirect('forming_header')
            else:
                messages.warning(request, 'Ресурсы не выбраны')
                return redirect('resources_formset')
    else:
        if request.session.get('ticket_tr_id'):
            ticket_tr_id = request.session['ticket_tr_id']
            ticket_tr = TR.objects.get(id=ticket_tr_id)
            task_otpm = ticket_tr.ticket_k.task_otpm
        else:
            task_otpm = None
        formset = ListResourcesFormSet()
        ono_for_formset = []
        for resource_for_formset in ono:
            resource_for_formset.pop(2)
            resource_for_formset.pop(1)
            resource_for_formset.pop(0)
            ono_for_formset.append(resource_for_formset)
        context = {
            'ono_for_formset': ono_for_formset,
            'formset': formset,
            'task_otpm': task_otpm
        }
        return render(request, 'tickets/resources_formset.html', context)


def job_formset(request):
    """Данный метод получает спискок услуг из ТР. Отображает форму, в которой пользователь для каждой услуги выбирает
    необходимое действие(перенос, изменение, организация) и формируется соответствующие списки услуг."""
    head = request.session['head']
    ticket_tr_id = request.session['ticket_tr_id']
    ticket_tr = TR.objects.get(id=ticket_tr_id)
    oattr = ticket_tr.oattr
    pps = ticket_tr.pps
    services = ticket_tr.services
    services_con = []
    for service in services:
        if service.startswith('Телефон'):
            if len(services_con) != 0:
                for i in range(len(services_con)):
                    if services_con[i].startswith('Телефон'):
                        services_con[i] = services_con[i] +' '+ service[len('Телефон'):]
                        break
                    else:
                        if i == len(services_con)-1:
                            services_con.append(service)
            else:
                services_con.append(service)
        elif service.startswith('ЛВС'):
            if len(services_con) != 0:
                for i in range(len(services_con)):
                    if services_con[i].startswith('ЛВС'):
                        services_con[i] = services_con[i] +' '+ service[len('ЛВС'):]
                        break
                    else:
                        if i == len(services_con)-1:
                            services_con.append(service)
            else:
                services_con.append(service)
        elif service.startswith('Видеонаблюдение'):
            if len(services_con) != 0:
                for i in range(len(services_con)):
                    if services_con[i].startswith('Видеонаблюдение'):
                        services_con[i] = services_con[i] +' '+ service[len('Видеонаблюдение'):]
                        break
                    else:
                        if i == len(services_con) - 1:
                            services_con.append(service)
            else:
                services_con.append(service)
        elif service.startswith('HotSpot'):
            if len(services_con) != 0:
                for i in range(len(services_con)):
                    if services_con[i].startswith('HotSpot'):
                        services_con[i] = services_con[i] +' '+ service[len('HotSpot'):]
                        break
                    else:
                        if i == len(services_con) - 1:
                            services_con.append(service)
            else:
                services_con.append(service)
        else:
            services_con.append(service)
    services = services_con
    ListJobsFormSet = formset_factory(ListJobsForm, extra=len(services))
    if request.method == 'POST':
        formset = ListJobsFormSet(request.POST)
        if formset.is_valid():
            pass_job_services = []
            change_job_services = []
            new_job_services = []
            data = formset.cleaned_data
            selected = zip(services, data)
            for services, data in selected:
                if data == {'jobs': 'Организация/Изменение, СПД'}:
                    new_job_services.append(services)
                elif data == {'jobs': 'Перенос, СПД'}:
                    pass_job_services.append(services)
                elif data == {'jobs': 'Изменение, не СПД'}:
                    change_job_services.append(services)
                elif data == {'jobs': 'Не требуется'}:
                    pass
            request.session['new_job_services'] = new_job_services
            request.session['pass_job_services'] = pass_job_services
            request.session['change_job_services'] = change_job_services
            return redirect('project_tr_exist_cl')
    else:
        formset = ListJobsFormSet()
        context = {
            'head': head,
            'oattr': oattr,
            'pps': pps,
            'services': services,
            'formset': formset
        }
        return render(request, 'tickets/job_formset.html', context)


@cache_check
def forming_header(request):
    """Данный метод проверяет если клиент подключен через CSW или WDA, то проверяет наличие на этих устройтсвах других
     договоров и если есть такие договоры, то добавляет их ресурсы в список выбранных ресурсов с договора клиента."""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    selected_ono = request.session['selected_ono']

    selected_client = selected_ono[0][0]
    selected_device = selected_ono[0][-2]
    request.session['selected_device'] = selected_device
    request.session['selected_client'] = selected_client
    if selected_device.startswith('CSW') or selected_device.startswith('WDA'):
        extra_selected_ono = _get_extra_selected_ono(username, password, selected_device, selected_client)
        if extra_selected_ono:
            for i in extra_selected_ono:
                selected_ono.append(i)

    request.session['selected_ono'] = selected_ono
    context = {
        'ono': selected_ono,

    }
    return redirect('forming_chain_header')


@cache_check
def forming_chain_header(request):
    """Данный метод собирает данные обо всех устройствах через которые подключен клиент и отправляет на страницу
    формирования заголовка из этих данных"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    chain_device = request.session['selected_device']
    selected_ono = request.session['selected_ono']
    phone_exist = request.session['phone_exist']
    chains = _get_chain_data(username, password, chain_device)
    if chains:
        downlink = _get_downlink(chains, chain_device)
        node_device = _get_node_device(chains, chain_device)
        nodes_vgw = []
        if phone_exist or node_device.endswith(', КК') or node_device.endswith(', WiFi'):
            vgw_on_node = _get_vgw_on_node(chains, chain_device)
            if vgw_on_node:
                nodes_vgw.append(chain_device)
        max_level = 20
        uplink, max_level = _get_uplink(chains, chain_device, max_level)
        all_chain = _get_all_chain(chains, chain_device, uplink, max_level)
        selected_client = 'No client'
        if all_chain[0] == None:
            node_uplink = node_device
            if phone_exist:
                extra_node_device = _get_extra_node_device(chains, chain_device, node_device)
                if extra_node_device:
                    for extra in extra_node_device:
                        extra_chains = _get_chain_data(username, password, extra)
                        extra_vgw = _get_vgw_on_node(extra_chains, extra)
                        if extra_vgw:
                            nodes_vgw.append(extra)
        else:
            node_uplink = _get_node_device(chains, all_chain[-1].split()[0])
            for all_chain_device in all_chain:
                if all_chain_device.startswith('CSW'):
                    extra_chains = _get_chain_data(username, password, all_chain_device)
                    extra_vgw = _get_vgw_on_node(extra_chains, all_chain_device)
                    if extra_vgw:
                        nodes_vgw.append(all_chain_device)
                    extra_selected_ono = _get_extra_selected_ono(username, password, all_chain_device, selected_client)
                    if extra_selected_ono:
                        for i in extra_selected_ono:
                            selected_ono.append(i)
        if downlink:
            for link_device in downlink:
                extra_vgw = _get_vgw_on_node(chains, link_device)
                if extra_vgw:
                    nodes_vgw.append(link_device)
                extra_selected_ono = _get_extra_selected_ono(username, password, link_device, selected_client)
                if extra_selected_ono:
                    for i in extra_selected_ono:
                        selected_ono.append(i)

        all_vgws = []
        if nodes_vgw:
            for i in nodes_vgw:
                parsing_vgws = _parsing_vgws_by_node_name(username, password, Switch=i)
                for vgw in parsing_vgws:
                    all_vgws.append(vgw)
        selected_clients_for_vgw = [client[0] for client in selected_ono]
        contracts_for_vgw = list(set(selected_clients_for_vgw))
        selected_vgw, waste_vgw = check_client_on_vgw(contracts_for_vgw, all_vgws, username, password)
        request.session['node_mon'] = node_uplink
        request.session['uplink'] = all_chain
        request.session['downlink'] = downlink
        request.session['vgw_chains'] = selected_vgw
        request.session['waste_vgw'] = waste_vgw
        return redirect('head')
    else:
        return redirect('no_data')


@cache_check
def head(request):
    """Данный метод приводит данные для заголовка в читаемый формат на основе шаблона в КБЗ и отправляет на страницу
    выбора шаблонов для ТР"""
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    node_mon = request.session['node_mon']
    uplink = request.session['uplink']
    downlink = request.session['downlink']
    vgw_chains = request.session['vgw_chains']
    selected_ono = request.session['selected_ono']
    waste_vgw = request.session['waste_vgw']

    templates = ckb_parse(username, password)
    result_services = []
    switch_config = None
    static_vars = {}
    hidden_vars = {}
    stroka = templates.get("Заголовок")
    static_vars['указать номер договора'] = selected_ono[0][0]
    static_vars['указать название клиента'] = selected_ono[0][1]
    static_vars['указать точку подключения'] = selected_ono[0][3]
    node_templates = {', РУА': 'РУА ', ', УА': 'УПА ', ', АВ': 'ППС ', ', КК': 'КК ', ', WiFi': 'WiFi '}
    for key, item in node_templates.items():
        if node_mon.endswith(key):
            finish_node = item + node_mon[:node_mon.index(key)]
            request.session['independent_pps'] = node_mon
    static_vars['указать узел связи'] = finish_node
    if uplink == [None]:
        static_vars['указать название коммутатора'] = selected_ono[0][-2]
        request.session['independent_kad'] = selected_ono[0][-2]
        static_vars['указать порт'] = selected_ono[0][-1]
        index_of_device = stroka.index('<- порт %указать порт%>') + len('<- порт %указать порт%>') + 1
        stroka = stroka[:index_of_device] + ' \n' + stroka[index_of_device:]
    else:
        static_vars['указать название коммутатора'] = uplink[-1].split()[0]
        request.session['independent_kad'] = uplink[-1].split()[0]
        static_vars['указать порт'] = ' '.join(uplink[-1].split()[1:])
        list_stroka_device = []
        if len(uplink) > 1:
            for i in range(len(uplink)-2, -1, -1):
                extra_stroka_device = '- {}\n'.format(uplink[i])
                list_stroka_device.append(extra_stroka_device)
            if selected_ono[0][-2].startswith('WDA'):
                extra_stroka_device = '- {}\n'.format(_replace_wda_wds(selected_ono[0][-2]))
                list_stroka_device.append(extra_stroka_device)
                extra_stroka_device = '- {}\n'.format(selected_ono[0][-2])
                list_stroka_device.append(extra_stroka_device)
            else:
                extra_stroka_device = '- {}\n'.format(selected_ono[0][-2])
                list_stroka_device.append(extra_stroka_device)
        elif len(uplink) == 1:
            if selected_ono[0][-2].startswith('WDA'):
                extra_stroka_device = '- {}\n'.format(_replace_wda_wds(selected_ono[0][-2]))
                list_stroka_device.append(extra_stroka_device)
                extra_stroka_device = '- {}\n'.format(selected_ono[0][-2])
                list_stroka_device.append(extra_stroka_device)
            else:
                extra_stroka_device = '- {}\n'.format(selected_ono[0][-2])
                list_stroka_device.append(extra_stroka_device)
        if downlink:
            for i in range(len(downlink)-1, -1, -1):
                extra_stroka_device = '- {}\n'.format(downlink[i])
                list_stroka_device.append(extra_stroka_device)
        extra_extra_stroka_device = ''.join(list_stroka_device)
        index_of_device = stroka.index('<- порт %указать порт%>') + len('<- порт %указать порт%>') + 1
        stroka = stroka[:index_of_device] + extra_extra_stroka_device + ' \n' + stroka[index_of_device:]
    if selected_ono[0][-2].startswith('CSW'):
        old_model_csw, node_csw = _parsing_model_and_node_client_device_by_device_name(selected_ono[0][-2], username,
                                                                                       password)
        switch_config = get_sw_config(selected_ono[0][-2], username, password)

        request.session['old_model_csw'] = old_model_csw
        request.session['node_csw'] = node_csw

    service_shpd = ['DA', 'BB', 'inet', 'Inet', '128 -', '53 -', '34 -', '33 -', '32 -', '54 -', '57 -', '60 -', '62 -',
                    '64 -', '68 -', '92 -', '96 -', '101 -', '105 -', '125 -', '107 -', '109 -', '483 -']
    service_shpd_bgp = ['BGP', 'bgp']
    service_portvk = ['-vk', 'vk-', '- vk', 'vk -', 'zhkh']
    service_portvm = ['-vrf', 'vrf-', '- vrf', 'vrf -']
    service_hotspot = ['hotspot']
    service_itv = ['itv']
    list_stroka_main_client_service = []
    list_stroka_other_client_service = []
    readable_services = dict()
    counter_exist_line = set()
    stick = False
    counter_stick = 0
    port_stick = set()
    for i in selected_ono:
        if selected_ono[0][0] == i[0]:
            if i[2] == 'IP-адрес или подсеть':
                if any(serv in i[-3] for serv in service_shpd_bgp) or '212.49.97.' in i[-4]:
                    extra_stroka_main_client_service = f'- услугу "Подключение по BGP" c реквизитами "{i[-4]}"({i[-2]} {i[-1]})\n'
                    if list_stroka_main_client_service:
                        for ind, main in enumerate(list_stroka_main_client_service):
                            if i[-1] in main:
                                main = main[
                                       :main.index('"(')] + f', услугу "Подключение по BGP" c реквизитами "{i[-4]}"' + main[
                                                                                                                   main.index(
                                                                                                                       '"('):]
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('"Подключение по BGP"')
                    readable_services = _readable(curr_value, readable_services, '"Подключение по BGP"', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3] for serv in service_shpd):
                    if switch_config:
                        service_ports = get_extra_service_port_csw(i[-1], switch_config, old_model_csw)
                        extra_stroka_main_client_service = f'- услугу "ШПД в интернет" c реквизитами "{i[-4]}"({i[-2]} {service_ports})\n'
                    else:
                        extra_stroka_main_client_service = f'- услугу "ШПД в интернет" c реквизитами "{i[-4]}"({i[-2]} {i[-1]})\n'
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('"ШПД в интернет"')
                    readable_services = _readable(curr_value, readable_services, '"ШПД в интернет"', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_hotspot):
                    if switch_config:
                        service_ports = get_extra_service_port_csw(i[-1], switch_config, old_model_csw)
                        extra_stroka_main_client_service = f'- услугу Хот-спот c реквизитами "{i[-4]}"({i[-2]} {service_ports})\n'
                    else:
                        extra_stroka_main_client_service = f'- услугу Хот-спот c реквизитами "{i[-4]}"({i[-2]} {i[-1]})\n'
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('Хот-спот')
                    readable_services = _readable(curr_value, readable_services, 'Хот-спот', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_itv):
                    if switch_config:
                        service_ports = get_extra_service_port_csw(i[-1], switch_config, old_model_csw)
                        extra_stroka_main_client_service = f'- услугу Вебург.ТВ c реквизитами "{i[-4]}"({i[-2]} {service_ports})\n'
                    else:
                        extra_stroka_main_client_service = f'- услугу Вебург.ТВ c реквизитами "{i[-4]}"({i[-2]} {i[-1]})\n'
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('Вебург.ТВ')
                    readable_services = _readable(curr_value, readable_services, 'Вебург.ТВ', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
            elif i[2] == 'Порт виртуального коммутатора':
                if any(serv in i[-3].lower() for serv in service_portvk):
                    extra_stroka_main_client_service = f'- услугу Порт ВЛС "{i[4]}"({i[-2]} {i[-1]})\n'
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('Порт ВЛС')
                    readable_services = _readable(curr_value, readable_services, 'Порт ВЛС', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_portvm):
                    extra_stroka_main_client_service = f'- услугу Порт ВМ "{i[4]}"({i[-2]} {i[-1]})\n'
                    list_stroka_main_client_service.append(extra_stroka_main_client_service)
                    curr_value = readable_services.get('Порт ВМ')
                    readable_services = _readable(curr_value, readable_services, 'Порт ВМ', i[-4])
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
            elif i[2] == 'Etherline':
                counter_stick += 1
                port_stick.add(i[-1])
                if 'Физический стык' in i[4]:
                    stick = True
                    break
                else:
                    if counter_stick == 5 and len(port_stick) == 1:
                        stick = True
                        break
                extra_stroka_main_client_service = f'- услугу ЦКС "{i[4]}"({i[-2]} {i[-1]})\n'
                list_stroka_main_client_service.append(extra_stroka_main_client_service)
                curr_value = readable_services.get('ЦКС')
                readable_services = _readable(curr_value, readable_services, 'ЦКС', i[-4])
                counter_exist_line.add(f'{i[-2]} {i[-1]}')
        else:
            if i[2] == 'IP-адрес или подсеть':
                if any(serv in i[-3] for serv in service_shpd):
                    extra_stroka_other_client_service = f'- услугу "ШПД в интернет" c реквизитами "{i[-4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                    list_stroka_other_client_service.append(extra_stroka_other_client_service)
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_hotspot):
                    extra_stroka_other_client_service = f'- услугу Хот-спот c реквизитами "{i[-4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                    list_stroka_other_client_service.append(extra_stroka_other_client_service)
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_itv):
                    extra_stroka_other_client_service = f'- услугу Вебург.ТВ c реквизитами "{i[-4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                    list_stroka_other_client_service.append(extra_stroka_other_client_service)
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
            elif i[2] == 'Порт виртуального коммутатора':
                if any(serv in i[-3].lower() for serv in service_portvk):
                    extra_stroka_other_client_service = f'- услугу Порт ВЛС "{i[4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                    list_stroka_other_client_service.append(extra_stroka_other_client_service)
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
                elif any(serv in i[-3].lower() for serv in service_portvm):
                    extra_stroka_other_client_service = f'- услугу Порт ВМ "{i[4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                    list_stroka_other_client_service.append(extra_stroka_other_client_service)
                    counter_exist_line.add(f'{i[-2]} {i[-1]}')
            elif i[2] == 'Etherline':
                extra_stroka_other_client_service = f'- услугу ЦКС "{i[4]}"({i[-2]} {i[-1]}) по договору {i[0]} {i[1]}\n'
                list_stroka_other_client_service.append(extra_stroka_other_client_service)
                counter_exist_line.add(f'{i[-2]} {i[-1]}')
    if not stick:
        if vgw_chains:
            old_name_model_vgws = []
            for i in vgw_chains:
                model = i.get('model')
                name = i.get('name')
                vgw_uplink = i.get('uplink').replace('\r\n', '')
                room = i.get('type')
                if model == 'ITM SIP':
                    extra_stroka_main_client_service = f'- услугу "Телефония" через IP-транк {name} ({vgw_uplink})'
                    counter_exist_line.add(f'{vgw_uplink}')
                    readable_services.update({'"Телефония"': 'через IP-транк'})
                else:
                    extra_stroka_main_client_service = f'- услугу "Телефония" через тел. шлюз {model} {name} ({vgw_uplink}). Место установки: {room}\n'
                    old_name_model_vgws.append(f'{model} {name}')
                    readable_services.update({'"Телефония"': None})
                list_stroka_main_client_service.append(extra_stroka_main_client_service)
                readable_services.update({'"Телефония"': None})
            if old_name_model_vgws:
                request.session['old_name_model_vgws'] = ', '.join(old_name_model_vgws)
        extra_extra_stroka_main_client_service = ''.join(list_stroka_main_client_service)
        extra_extra_stroka_other_client_service = ''.join(list_stroka_other_client_service)
        index_of_service = stroka.index('В данной точке %клиент потребляет/c клиентом организован L2-стык%') + len('В данной точке %клиент потребляет/c клиентом организован L2-стык%')+1
        stroka = stroka[:index_of_service] + extra_extra_stroka_main_client_service + '\n' + extra_extra_stroka_other_client_service + stroka[index_of_service:]
        if selected_ono[0][-2].startswith('CSW') or selected_ono[0][-2].startswith('WDA'):
            if waste_vgw:
                list_stroka_other_vgw =[]
                for i in waste_vgw:
                    model = i.get('model')
                    name = i.get('name')
                    vgw_uplink = i.get('uplink').replace('\r\n', '')
                    room = i.get('type')
                    contracts = i.get('contracts')
                    if bool(contracts) == False:
                        contracts = 'Нет контрактов'
                    if model == 'ITM SIP':
                        extra_stroka_other_vgw = f'Также есть подключение по IP-транк {name} ({vgw_uplink}). Контракт: {contracts}\n'
                    else:
                        extra_stroka_other_vgw = f'Также есть тел. шлюз {model} {name} ({vgw_uplink}). Контракт: {contracts}\n'
                    list_stroka_other_vgw.append(extra_stroka_other_vgw)
                extra_stroka_other_vgw = ''.join(list_stroka_other_vgw)
                stroka = stroka + '\n' + extra_stroka_other_vgw
        counter_exist_line = len(counter_exist_line)
        static_vars['клиент потребляет/c клиентом организован L2-стык'] = 'клиент потребляет:'
        if (selected_ono[0][-2].startswith('SW') and counter_exist_line > 1) or (selected_ono[0][-2].startswith('IAS') and counter_exist_line > 1) or (selected_ono[0][-2].startswith('AR') and counter_exist_line > 1):
            pass
        else:
            hidden_vars['- порт %указать порт%'] = '- порт %указать порт%'
    else:
        static_vars['клиент потребляет/c клиентом организован L2-стык'] = 'c клиентом организован L2-стык.'
        hidden_vars['- порт %указать порт%'] = '- порт %указать порт%'
        counter_exist_line = 0
        request.session['stick'] = True
    result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
    result_services = ''.join(result_services)
    rev_result_services = result_services[::-1]
    index_of_head = rev_result_services.index('''-----------------------------------------------------------------------------------\n''')
    rev_result_services = rev_result_services[:index_of_head]
    head = rev_result_services[::-1]
    request.session['head'] = head.strip()
    request.session['readable_services'] = readable_services
    request.session['counter_exist_line'] = counter_exist_line
    if request.session.get('ticket_tr_id'):
        return redirect('job_formset')
    else:
        return redirect('title_tr')


@cache_check
def add_tr_exist_cl(request, dID, tID, trID):
    """Данный метод работает для существующей точки подключения. Получает данные о ТР в СПП, добавляет ТР в БД,
    перенаправляет на страницу запроса контракта клиента. """
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    tr_params = for_tr_view(username, password, dID, tID, trID)
    if tr_params.get('Access denied') == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        ticket_spp_id = request.session['ticket_spp_id']
        ticket_tr_id = add_tr_to_db(dID, trID, tr_params, ticket_spp_id)
        spplink = 'https://sss.corp.itmh.ru/dem_tr/dem_begin.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)
        request.session['spplink'] = spplink
        request.session['ticket_tr_id'] = ticket_tr_id
        return redirect('get_resources')


@cache_check
def add_tr_not_required(request, dID, tID, trID):
    """Данный метод работает для существующей точки подключения. Получает данные о ТР в СПП, добавляет ТР в БД,
    перенаправляет на страницу запроса контракта клиента. """
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    tr_params = for_tr_view(username, password, dID, tID, trID)
    if tr_params.get('Access denied') == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response
    else:
        ticket_spp_id = request.session['ticket_spp_id']
        ticket_tr_id = add_tr_to_db(dID, trID, tr_params, ticket_spp_id)
        spplink = 'https://sss.corp.itmh.ru/dem_tr/dem_begin.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)
        request.session['spplink'] = spplink
        ticket_tr = TR.objects.get(id=ticket_tr_id)
        services_plus_desc = ticket_tr.services
        oattr = ticket_tr.oattr
        request.session['services_plus_desc'] = services_plus_desc
        request.session['oattr'] = oattr
        request.session['ticket_tr_id'] = ticket_tr_id
        request.session['not_required'] = True
        return redirect('data')




def project_tr_exist_cl(request):
    """Данный метод формирует последовательность url'ов по которым необходимо пройти для получения данных от
     пользователя и перенаправляет на первый из них. Используется для существующей точки подключения."""
    ticket_tr_id = request.session['ticket_tr_id']
    ticket_tr = TR.objects.get(id=ticket_tr_id)
    oattr = ticket_tr.oattr
    pps = ticket_tr.pps
    pps = pps.strip()
    turnoff = ticket_tr.turnoff
    task_otpm = ticket_tr.ticket_k.task_otpm
    services_plus_desc = ticket_tr.services
    des_tr = ticket_tr.ticket_k.des_tr
    address = None
    for i in range(len(des_tr)):
        if ticket_tr.ticket_tr in next(iter(des_tr[i].keys())):
            while address == None:
                if next(iter(des_tr[i].values())):
                    i -= 1
                else:
                    address = next(iter(des_tr[i].keys()))
                    address = address.replace(', д.', ' ')
    request.session['address'] = address
    cks_points = []
    for point in des_tr:
        if next(iter(point.keys())).startswith('г.'):
            cks_points.append(next(iter(point.keys())).split('ул.')[1])
    request.session['cks_points'] = cks_points
    request.session['services_plus_desc'] = services_plus_desc
    request.session['task_otpm'] = task_otpm
    request.session['pps'] = pps
    if oattr:
        request.session['oattr'] = oattr
        wireless_temp = ['БС ', 'радио', 'радиоканал', 'антенну']
        ftth_temp = ['Alpha', 'ОК-1']
        vols_temp = ['ОВ', 'ОК', 'ВОЛС', 'волокно', 'ОР ', 'ОР№', 'сущ.ОМ', 'оптическ']
        if any(wl in oattr for wl in wireless_temp) and (not 'ОК' in oattr):
            sreda = '3'
        elif any(ft in oattr for ft in ftth_temp) and (not 'ОК-16' in oattr):
            sreda = '4'
        elif any(vo in oattr for vo in vols_temp):
            sreda = '2'
        else:
            sreda = '1'
    else:
        request.session['oattr'] = None
        sreda = '1'
        request.session['sreda'] = '1'
    new_job_services = request.session['new_job_services']
    pass_job_services = request.session['pass_job_services']
    change_job_services = request.session['change_job_services']
    type_pass = []
    tag_service = []
    if pass_job_services:
        type_pass.append('Перенос, СПД')
        tag_service.append({'pass_serv': None})

    if new_job_services:
        type_pass.append('Организация/Изменение, СПД')
        counter_line_services, hotspot_points, services_plus_desc = _counter_line_services(new_job_services)
        new_job_services = services_plus_desc
        tags, hotspot_users, premium_plus = _tag_service_for_new_serv(new_job_services)
        for tag in tags:
            tag_service.append(tag)
        request.session['new_job_services'] = new_job_services
        if change_job_services:
            type_pass.append('Изменение, не СПД')
            tags, hotspot_users, premium_plus = _tag_service_for_new_serv(change_job_services)
            for tag in tags:
                tag_service.insert(0, tag)
                tag_service.insert(0, {'change_serv': None})

        if counter_line_services == 0:
            tag_service.append({'data': None})
        else:
            if sreda == '1':
                tag_service.append({'copper': None})
            elif sreda == '2' or sreda == '4':
                tag_service.append({'vols': None})
            elif sreda == '3':
                tag_service.append({'wireless': None})

        request.session['hotspot_points'] = hotspot_points
        request.session['hotspot_users'] = hotspot_users
        request.session['premium_plus'] = premium_plus
        request.session['counter_line_services'] = counter_line_services
        request.session['services_plus_desc'] = services_plus_desc
        request.session['counter_line_services'] = counter_line_services

    if change_job_services and not new_job_services and not pass_job_services:
        type_pass.append('Изменение, не СПД')
        tags, hotspot_users, premium_plus = _tag_service_for_new_serv(change_job_services)
        for tag in tags:
            tag_service.insert(0, tag)
            tag_service.insert(0, {'change_serv': None})
        tag_service.append({'data': None})

    request.session['oattr'] = oattr
    request.session['pps'] = pps
    request.session['turnoff'] = turnoff
    request.session['sreda'] = sreda
    request.session['type_pass'] = type_pass
    request.session['tag_service'] = tag_service
    return redirect(next(iter(tag_service[0])))


def change_serv(request):
    """Данный метод отображает форму для выбора изменения услуги ШПД или организации услуг ШПД, ЦКС, порт ВК, порт ВМ
    без монтаж. работ"""
    if request.method == 'POST':
        changeservform = ChangeServForm(request.POST)
        if changeservform.is_valid():
            type_change_service = changeservform.cleaned_data['type_change_service']
            try:
                types_change_service = request.session['types_change_service']
            except KeyError:
                types_change_service = []
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            types_change_service.append({type_change_service: next(iter(tag_service[0].values()))})
            if type_change_service == "Организация доп IPv6":
                if len(tag_service) == 0:
                    tag_service.append({'data': None})
            else:
                tag_service.insert(0, {'change_params_serv': None})
            request.session['types_change_service'] = types_change_service
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        changeservform = ChangeServForm()
        tag_service = request.session['tag_service']
        service = next(iter(tag_service[1].values()))
        context = {
            'changeservform': changeservform,
            'service': service
        }
        return render(request, 'tickets/change_serv.html', context)


def change_params_serv(request):
    """Данный метод отображает форму с параметрами услуги ШПД(новая подсеть/маршрутизируемая подсеть)"""
    if request.method == 'POST':
        changeparamsform = ChangeParamsForm(request.POST)
        if changeparamsform.is_valid():
            new_mask = changeparamsform.cleaned_data['new_mask']
            routed_ip = changeparamsform.cleaned_data['routed_ip']
            routed_vrf = changeparamsform.cleaned_data['routed_vrf']
            request.session['new_mask'] = new_mask
            request.session['routed_ip'] = routed_ip
            request.session['routed_vrf'] = routed_vrf
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if len(tag_service) == 0:
                tag_service.append({'data': None})
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))
    else:
        head = request.session['head']
        types_change_service = request.session['types_change_service']
        for i in range(len(types_change_service)):
            types_cks_vk_vm_trunk = [
                "Организация порта ВМ trunk'ом",
                "Организация порта ВЛС trunk'ом",
                "Организация ЦКС trunk'ом",
                "Организация ШПД trunk'ом",
                "Организация ШПД trunk'ом с простоем",
                "Организация ЦКС trunk'ом с простоем",
                "Организация порта ВЛС trunk'ом с простоем",
                "Организация порта ВМ trunk'ом с простоем"
            ]
            if next(iter(types_change_service[i].keys())) in types_cks_vk_vm_trunk:
                tag_service = request.session['tag_service']
                tag_service.pop(0)
                if next(iter(types_change_service[i].keys())) == "Организация ШПД trunk'ом":
                    tag_service.pop(0)
                request.session['tag_service'] = tag_service
                return redirect(next(iter(tag_service[0])))

            types_only_mask = ["Организация доп connected",
                               "Замена connected на connected",
                               "Изменение cхемы организации ШПД"
                               ]
            if next(iter(types_change_service[i].keys())) in types_only_mask:
                only_mask = True
                tag_service = request.session['tag_service']
                tag_service.pop(0)
                request.session['tag_service'] = tag_service
            else:
                only_mask = False
            if next(iter(types_change_service[i].keys())) == "Организация доп маршрутизируемой":
                routed = True
                tag_service = request.session['tag_service']
                tag_service.pop(0)
                request.session['tag_service'] = tag_service
            else:
                routed = False
        changeparamsform = ChangeParamsForm()
        context = {
            'head': head,
            'changeparamsform': changeparamsform,
            'only_mask': only_mask,
            'routed': routed
        }
        return render(request, 'tickets/change_params_serv.html', context)


def change_log_shpd(request):
    """Данный метод отображает форму выбора для услуги ШПД новой адресации или существующей"""
    if request.method == 'POST':
        changelogshpdform = ChangeLogShpdForm(request.POST)
        if changelogshpdform.is_valid():
            change_log_shpd = changelogshpdform.cleaned_data['change_log_shpd']
            request.session['change_log_shpd'] = change_log_shpd
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            return redirect(next(iter(tag_service[0])))
    else:
        head = request.session['head']
        kad = request.session['kad']
        subnet_for_change_log_shpd = request.session['subnet_for_change_log_shpd']
        changelogshpdform = ChangeLogShpdForm()
        if request.session.get('pass_job_services'):
            services = request.session.get('pass_job_services')
        elif request.session.get('new_job_services'):
            services = request.session.get('new_job_services')
        else:
            services = None
        context = {
            'head': head,
            'kad': kad,
            'subnet_for_change_log_shpd': subnet_for_change_log_shpd,
            'pass_job_services': services,
            'changelogshpdform': changelogshpdform
        }
        return render(request, 'tickets/change_log_shpd.html', context)


def params_extend_service(request):
    """Данный метод отображает форму с параметрами скорости и ограничения полосы для расширения услуг ЦКС, порт ВК,
    порт ВМ"""
    if request.method == 'POST':
        extendserviceform = ExtendServiceForm(request.POST)

        if extendserviceform.is_valid():
            extend_speed = extendserviceform.cleaned_data['extend_speed']
            extend_policer_cks_vk = extendserviceform.cleaned_data['extend_policer_cks_vk']
            extend_policer_vm = extendserviceform.cleaned_data['extend_policer_vm']
            request.session['extend_speed'] = extend_speed
            request.session['extend_policer_cks_vk'] = extend_policer_cks_vk
            request.session['extend_policer_vm'] = extend_policer_vm
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if len(tag_service) == 0:
                tag_service.append({'data': None})
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))

    else:
        desc_service = request.session.get('desc_service')
        extendserviceform = ExtendServiceForm()
        pass_job_services = request.session.get('pass_job_services')
        context = {
            'desc_service': desc_service,
            'pass_job_services': pass_job_services,
            'extendserviceform': extendserviceform
        }
        return render(request, 'tickets/params_extend_service.html', context)


def pass_serv(request):
    """Данный метод отображает форму с параметрами переноса/расширения услуг"""
    if request.method == 'POST':
        passservform = PassServForm(request.POST)
        if passservform.is_valid():
            type_passage = passservform.cleaned_data['type_passage']
            change_log = passservform.cleaned_data['change_log']
            exist_sreda = passservform.cleaned_data['exist_sreda']
            request.session['type_passage'] = type_passage
            request.session['change_log'] = change_log
            request.session['exist_sreda'] = exist_sreda
            tag_service = request.session['tag_service']
            readable_services = request.session['readable_services']
            selected_ono = request.session['selected_ono']
            type_pass = request.session['type_pass']
            sreda = request.session['sreda']
            tag_service.pop(0)
            if 'Перенос, СПД' not in type_pass:
                return redirect(next(iter(tag_service[0])))
            else:
                pass_job_services = request.session.get('pass_job_services')
                if change_log == 'Порт и КАД не меняется':
                    if type_passage == 'Перевод на гигабит':
                        desc_service, _ = get_selected_readable_service(readable_services, selected_ono)
                        if desc_service in ['ЦКС', 'Порт ВЛС', 'Порт ВМ']:
                            request.session['desc_service'] = desc_service
                            tag_service.insert(0, {'params_extend_service': None})
                            return redirect(next(iter(tag_service[0])))
                    elif (type_passage == 'Перенос точки подключения' or type_passage == 'Перенос логического подключения') and request.session.get('turnoff'):
                        tag_service.insert(0, {'pass_turnoff': None})
                        return redirect(next(iter(tag_service[0])))
                else:
                    if type_passage == 'Перевод на гигабит':
                        desc_service, _ = get_selected_readable_service(readable_services, selected_ono)
                        if desc_service in ['ЦКС', 'Порт ВЛС', 'Порт ВМ']:
                            request.session['desc_service'] = desc_service
                            tag_service.insert(0, {'params_extend_service': None})
                    phone_in_pass = [x for x in pass_job_services if x.startswith('Телефон')]
                    if phone_in_pass and 'CSW' not in request.session.get('selected_ono')[0][-2]:
                        tag_service.insert(0, {'phone': ''.join(phone_in_pass)})
                        request.session['phone_in_pass'] = ' '.join(phone_in_pass)
                    if any(tag in tag_service for tag in [{'copper': None}, {'vols': None}, {'wireless': None}]):
                        pass
                    else:
                        if {'data': None} in tag_service:
                            tag_service.remove({'data': None})
                        if sreda == '1':
                            tag_service.append({'copper': None})
                        elif sreda == '2' or sreda == '4':
                            tag_service.append({'vols': None})
                        elif sreda == '3':
                            tag_service.append({'wireless': None})
                if len(tag_service) == 0:
                    tag_service.append({'data': None})
                return redirect(next(iter(tag_service[0])))
    else:
        oattr = request.session['oattr']
        pps = request.session['pps']
        head = request.session['head']
        passservform = PassServForm()
        context = {
            'passservform': passservform,
            'oattr': oattr,
            'pps': pps,
            'head': head
        }
        return render(request, 'tickets/pass_serv.html', context)


def pass_turnoff(request):
    """Данный метод отображает форму для ввода ППР на случае если в ТР осуществляется перенос услуг без изменения
    логического подключения, но при этом в ТР заказано отключение других клиентов"""
    if request.method == 'POST':
        passturnoffform = PassTurnoffForm(request.POST)
        if passturnoffform.is_valid():
            ppr = passturnoffform.cleaned_data['ppr']
            request.session['ppr'] = ppr
            tag_service = request.session['tag_service']
            tag_service.pop(0)
            if len(tag_service) == 0:
                tag_service.append({'data': None})
            request.session['tag_service'] = tag_service
            return redirect(next(iter(tag_service[0])))

    else:
        oattr = request.session['oattr']
        pps = request.session['pps']
        head = request.session['head']
        spplink = request.session['spplink']
        regex_link = 'dem_tr\/dem_begin\.php\?dID=(\d+)&tID=(\d+)&trID=(\d+)'
        match_link = re.search(regex_link, spplink)
        dID = match_link.group(1)
        tID = match_link.group(2)
        trID = match_link.group(3)
        passturnoffform = PassTurnoffForm()
        context = {
            'passturnoffform': passturnoffform,
            'oattr': oattr,
            'pps': pps,
            'head': head,
            'dID': dID,
            'tID': tID,
            'trID': trID
        }
        return render(request, 'tickets/pass_turnoff.html', context)


def search(request):
    """Данный метод отображает html-страницу с поиском заявок"""
    searchticketsform = SearchTicketsForm(request.GET)
    if searchticketsform.is_valid():
        spp = searchticketsform.cleaned_data['spp']
        tr = searchticketsform.cleaned_data['tr']
        pps = searchticketsform.cleaned_data['pps']
        connection_point = searchticketsform.cleaned_data['connection_point']
        ortr = searchticketsform.cleaned_data['ortr']
        client = searchticketsform.cleaned_data['client']
        start = searchticketsform.cleaned_data['start']
        stop = searchticketsform.cleaned_data['stop']
        initial_params = {}
        if spp:
            initial_params.update({'spp': spp})
        if tr:
            initial_params.update({'tr': tr})
        if pps:
            initial_params.update({'pps': pps})
        if pps:
            initial_params.update({'connection_point': connection_point})
        if client:
            initial_params.update({'client': client})
        if ortr:
            initial_params.update({'ortr': ortr})
        if start:
            initial_params.update({'start': start})
        if stop:
            initial_params.update({'stop': stop})

        searchticketsform = SearchTicketsForm(initial=initial_params)
        context = {
            'searchticketsform': searchticketsform,
        }
        if request.GET:
            query = None
            if request.GET.get('spp'):
                query_spp = Q(ticket_k__ticket_k__icontains=spp)
                query = query_spp if query is None else query & query_spp
            if request.GET.get('tr'):
                query_tr = Q(ticket_tr__icontains=tr)
                query = query_tr if query is None else query & query_tr
            if request.GET.get('pps'):
                query_pps = Q(pps__icontains=pps)
                query = query_pps if query is None else query & query_pps
            if request.GET.get('connection_point'):
                query_connection_point = Q(connection_point__icontains=connection_point)
                query = query_connection_point if query is None else query & query_connection_point
            if request.GET.get('client'):
                query_client = Q(ticket_k__client__icontains=client)
                query = query_client if query is None else query & query_client
            if request.GET.get('ortr'):
                query_ortr = Q(ortrtr__ortr__icontains=ortr) | Q(ortrtr__ots__icontains=ortr)
                query = query_ortr if query is None else query & query_ortr
            if request.GET.get('start'):
                query_start = Q(ticket_k__created__gte=start)
                query = query_start if query is None else query & query_start
            if request.GET.get('stop'):
                query_stop = Q(ticket_k__complited__lt=stop)
                query = query_stop if query is None else query & query_stop
            if query is not None:
                results = TR.objects.filter(query).order_by('-ticket_k__created')
                paginator = Paginator(results, 50)
                page_number = request.GET.get('page')
                page_obj = paginator.get_page(page_number)
                context.update({'page_obj': page_obj}) # 'results': results

    else:
        context = {
            'searchticketsform': searchticketsform
        }
    return render(request, 'tickets/search.html', context)



def static_formset(request):
    """Не используется, задел на будущее"""
    template_static = """Присоединение к СПД по медной линии связи.
-----------------------------------------------------------------------------------

%ОИПМ/ОИПД% проведение работ.
- Организовать медную линию связи от %указать узел связи% до клиентcкого оборудования.
- Подключить организованную линию для клиента в коммутатор %указать название коммутатора%, порт задействовать %указать порт коммутатора%."""

    TemplatesStaticFormSet = formset_factory(TemplatesStaticForm, extra=4)
    if request.method == 'POST':
        formset = TemplatesStaticFormSet(request.POST)
        if formset.is_valid():

            data = formset.cleaned_data
            print('!!!!!!!!dataresources_formset')
            print(data)
            static_vav = ['ОИПМ/ОИПД', 'указать узел связи', 'указать название коммутатора', 'указать порт коммутатора']
            selected_ono = []
            unselected_ono = []
            static_vars = {}
            selected = zip(static_vav, data)
            for static_vav, data in selected:
                # static_vars.update({static_vav: data})
                static_vars[static_vav] = next(iter(data.values()))
            print('!!!!static_vars')
            print(static_vars)
            return redirect('no_data')
    else:
        template_static = """Присоединение к СПД по медной линии связи.
        -----------------------------------------------------------------------------------

        %ОИПМ/ОИПД% проведение работ.
        - Организовать медную линию связи от %указать узел связи% до клиентcкого оборудования.
        - Подключить организованную линию для клиента в коммутатор %указать название коммутатора%, порт задействовать %указать порт коммутатора%."""
        static_vav = ['ОИПМ/ОИПД', 'указать узел связи', 'указать название коммутатора', 'указать порт коммутатора']
        formset = TemplatesStaticFormSet()
        context = {
            'ono_for_formset': static_vav,
            # 'contract': contract,
            'formset': formset
        }

        return render(request, 'tickets/template_static_formset.html', context)

