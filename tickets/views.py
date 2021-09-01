from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from .models import TR, SPP, OrtrTR
from .forms import TrForm, PortForm, LinkForm, HotspotForm, SPPForm, ServiceForm, PhoneForm, ItvForm, ShpdForm,\
    VolsForm, CopperForm, WirelessForm, CswForm, CksForm, PortVKForm, PortVMForm, VideoForm, LvsForm, LocalForm, SksForm,\
    UserRegistrationForm, UserLoginForm, OrtrForm, AuthForServiceForm, ContractForm, ChainForm, ListResourcesForm

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404


def register(request):
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


def index(request):
    """Данный метод нужно будет удалить"""
    list_session_keys = []
    for key in request.session.keys():
        if key.startswith('_'):
            pass
        else:
            list_session_keys.append(key)
    for key in list_session_keys:
        del request.session[key]
    print(request.session.keys())

    tr = SPP.objects.order_by('-created')
    return render(request, 'tickets/index.html', {'tr': tr})

@login_required(login_url='login/')
def private_page(request):
    """Данный метод в Личном пространстве пользователя отображает все задачи этого пользователя"""
    request = flush_session_key(request)
    spp_success = SPP.objects.filter(user=request.user).order_by('-created')
    return render(request, 'tickets/private_page.html', {'spp_success': spp_success})



def get_tr(request, ticket_tr, ticket_id):
    """Данный метод можно будет удалить"""
    services_one_tr = []
    one_tr = TR.objects.get(ticket_tr=ticket_tr, id=ticket_id)
    for item in one_tr.servicestr_set.all():
        services_one_tr.append(item.service)
    data_one_tr = one_tr.datatr_set.get()
    ortr_one_tr = one_tr.ortrtr_set.first() #first вместо get, т.к. если записи нет, то будет исключение DoesNotExist
    context = {
        'one_tr': one_tr,
        'services_one_tr': services_one_tr,
        'data_one_tr': data_one_tr,
        'ortr_one_tr': ortr_one_tr
    }

    return render(request, 'tickets/tr.html', context=context)


import re
from requests.auth import HTTPBasicAuth
import requests
from bs4 import BeautifulSoup
from collections import OrderedDict
import itertools
import pymorphy2
import datetime


def stash(sw, model, login, password):
    """Данный метод принимает в качестве параметров Название КАД и модель КАД. Обращается к stash.itmh.ru и парсит
    конфиг коммутатора по названию. На основе модели КАД подставляет соответствующие regex для формирования данных по портам КАД"""
    url = 'https://stash.itmh.ru/projects/NMS/repos/pantera_extrim/raw/backups/' + sw + '-config?at=refs%2Fheads%2Fmaster'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 404:
        config_ports_device = {}
    else:
        switch = req.content.decode('utf-8')

        if 'SNR' in model or 'Cisco' in model or 'Orion' in model:
            port_list = []
            regex_description = '\wnterface (\S+\/\S+)(.+?)!'
            match_description = re.finditer(regex_description, switch, flags=re.DOTALL)
            # чтобы найти description блок интерфейса разделяется по \r\n, если не получается разделить, разделяется по \n
            config_ports_device = {}
            for i in match_description:
                if 'description' in i.group(2):
                    desc = i.group(2).split('\r\n')
                    if len(desc) == 1:
                        desc = i.group(2).split('\n')
                        if 'description' in desc[1]:
                            desc = i.group(2).split('\n')[1].split()[1]
                        else:
                            desc = i.group(2).split('\n')[2].split()[1]
                    else:
                        if 'description' in desc[1]:
                            desc = i.group(2).split('\r\n')[1].split()[1]
                        else:
                            desc = i.group(2).split('\r\n')[2].split()[1]
                else:
                    desc = '-'

                if 'switchport access vlan 4094' in i.group(2):
                    vlan = 'Заглушка 4094'
                else:
                    vlan = '-'

                config_ports_device[i.group(1)] = [desc, vlan]


        elif 'D-Link' in model:
            port_list = None
            config_ports_device = {}
            regex_description = 'config ports (\d+) (?:.+?) description (\".*?\")\n'
            match_description = re.finditer(regex_description, switch, flags=re.DOTALL)
            for i in match_description:
                config_ports_device['Port {}'.format(i.group(1))] = [i.group(2), '-']
            regex_free = 'config vlan stub add untagged (\S+)'
            match_free = re.search(regex_free, switch)
            port_free = []
            for i in match_free.group(1).split(','):
                if '-' in i:
                    start, stop = [int(j) for j in i.split('-')]
                    port_free += list(range(start, stop+1))
                else:
                    port_free.append(int(i))

            for i in port_free:
                if config_ports_device.get('Port {}'.format(i)):
                    config_ports_device['Port {}'.format(i)][1] = 'Заглушка 4094'
                else:
                    config_ports_device['Port {}'.format(i)] = ['-', 'Заглушка 4094']

    return config_ports_device

def match_cks(tochka, login, password):
    """Данный метод получает в параметр tochka(где содержатся dID и tID), по этим данным парсится страница ТР
     Точки подключения и получает из нее список всех точек подключения. С помощью библиотеки itertools формирует
      всевозможные варианты типа Точка А - Точка В"""
    list_cks = []
    list_strok = []
    url = 'https://sss.corp.itmh.ru/dem_tr/dem_point_panel.php?dID={}&amp;tID={}'.format(tochka[0], tochka[1])
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 200:
        cks_parsed = req.content.decode('utf-8')
        regex_cks = '\'>&nbsp;(.+?)&nbsp;<'
        match_cks = re.finditer(regex_cks, cks_parsed)
        # print(match_cks)
        for i in match_cks:
            list_cks.append(i.group(1))
        for i in itertools.combinations(list_cks,
                                        2):  # берет по очереди по 2 элемента списка не включая дубли и перевертыши
            list_strok.append(i[0] + ' - ' + i[1])

        return list_strok
    else:
        list_strok.append('Access denied')
        return list_strok



def trtr(request):
    """Данный метод можно удалять"""
    #context = {'services_plus_desc': services_plus_desc, 'pps': pps, 'turnoff': turnoff, 'oattr': oattr, 'success': success, 'linkform': linkform}
    return render(request, 'tickets/trtr.html')

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
                #prim = request.META.get('HTTP_REFERER')
                #print(prim)
                #cache.set_many({'username': username, 'password': password}, timeout=60)
                print(request.GET)
                if 'next' in request.GET:
                    return redirect(request.GET['next'])
                return redirect('ortr')
    else:
        authform = AuthForServiceForm()

    return render(request, 'tickets/login_is.html', {'form': authform})

from django.core.cache import cache

from django.contrib.auth.decorators import user_passes_test




from django.http import HttpResponseRedirect

def cache_check(func):
    """Данный декоратор осуществляет проверку, что пользователь авторизован в АРМ, и в redis есть его логин/пароль,
     если данных нет, то перенаправляет на страницу Авторизация в ИС Холдинга"""
    def wrapper(request, *args, **kwargs):
        print(request.path)
        if not request.user.is_authenticated:
            return redirect('login/?next=%s' % (request.path))#(request.GET['next']))
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        print(request.GET)
        #?next={}'.format(request.GET['next'])
        if credent == None:
            response = redirect('login_for_service')#, request.GET['next'])
            print(response['Location'])
            #response['Location'] += '?next={}'.format(request.GET['next'])
            response['Location'] += '?next={}'.format(request.path)
            return response
            #return redirect('login_for_service?next={}'.format(request.GET['next']))
        return func(request, *args, **kwargs)
    return wrapper


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
    search[:] = [x for x in search if 'ПТО' not in x[0]]
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response

    else:
        list_search = []
        for i in search:
            print('!!!')
            print(i[0])
            if 'ПТО' not in i[0]:
                list_search.append(i[0])
        print(list_search)
        spp_process = SPP.objects.filter(Q(process=True) | Q(wait=True)).filter(type_ticket='Коммерческая')
        list_spp_process = []
        for i in spp_process:
            list_spp_process.append(i.ticket_k)
        print(list_spp_process)
        list_search_rem = []
        for i in list_spp_process:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        print(list_search_rem)

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
    search[:] = [x for x in search if 'ПТО' in x[0]]
    if search[0] == 'Access denied':
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response

    else:
        list_search = []
        print(search)
        for i in search:
            if 'ПТО' in i[0]:
                list_search.append(i[0])
        # list_search = [i for i in set_search]
        print(list_search)
        spp_process = SPP.objects.filter(process=True).filter(type_ticket='ПТО')
        list_spp_process = []
        for i in spp_process:
            list_spp_process.append(i.ticket_k)
        print(list_spp_process)
        list_search_rem = []
        for i in list_spp_process:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        print(list_search_rem)


        search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
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
        for i in search:
            list_search.append(i[0])
        print(list_search)
        spp_proc_wait_all = SPP.objects.filter(Q(process=True) | Q(wait=True))
        list_spp_proc_wait_all = []
        for i in spp_proc_wait_all:
            list_spp_proc_wait_all.append(i.ticket_k)
        print(list_spp_proc_wait_all)
        list_search_rem = []
        for i in list_spp_proc_wait_all:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        print(list_search_rem)

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
            print(linkform.cleaned_data)
            spplink = linkform.cleaned_data['spplink']
            manlink = spplink
            regex_link = 'dem_tr\/dem_begin\.php\?dID=(\d+)&tID=(\d+)&trID=(\d+)'
            match_link = re.search(regex_link, spplink)
            if match_link:
                dID = match_link.group(1)
                tID = match_link.group(2)
                trID = match_link.group(3)

                request.session['manlink'] = manlink
                print(request.session.items())
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

        tag_service = []
        tag_service.append('sppdata')
        for index_service in range(len(services_plus_desc)):
            if 'Телефон' in services_plus_desc[index_service]:
                tag_service.append('phone')
            elif 'iTV' in services_plus_desc[index_service]:
                tag_service.append('itv')
            elif 'Интернет, DHCP' in services_plus_desc[index_service] or 'Интернет, блок Адресов Сети Интернет' in services_plus_desc[index_service]:
                tag_service.append('shpd')
            elif 'ЦКС' in services_plus_desc[index_service]:
                tag_service.append('cks')
            elif 'Порт ВЛС' in services_plus_desc[index_service]:
                tag_service.append('portvk')
            elif 'Порт ВМ' in services_plus_desc[index_service]:
                tag_service.append('portvm')
            elif 'Видеонаблюдение' in services_plus_desc[index_service]:
                tag_service.append('video')
            elif 'HotSpot' in services_plus_desc[index_service]:
                if ('премиум +' or 'премиум+') in services_plus_desc[index_service].lower():
                    premium_plus = True
                else:
                    premium_plus = False
                hotspot_users = None
                regex_hotspot_users = ['(\d+)посетит', '(\d+) посетит', '(\d+) польз', '(\d+)польз', '(\d+)чел',
                                               '(\d+) чел']
                for regex in regex_hotspot_users:
                    match_hotspot_users = re.search(regex, services_plus_desc[index_service])
                    if match_hotspot_users:
                        hotspot_users = match_hotspot_users.group(1)
                        break

                tag_service.append('hotspot')
                request.session['hotspot_points'] = hotspot_points
                request.session['hotspot_users'] = hotspot_users
                request.session['premium_plus'] = premium_plus
            elif 'ЛВС' in services_plus_desc[index_service]:
                tag_service.append('local')

        if counter_line_services == 0:
            tag_service.append('data')
        else:
            if sreda == '1':
                tag_service.append('copper')
            elif sreda == '2' or sreda == '4':
                tag_service.append('vols')
            elif sreda == '3':
                tag_service.append('wireless')

        request.session['tag_service'] = tag_service
        print('!!!!!tagsevice')
        print(tag_service)
        return redirect(tag_service[0])





#def inputtr(request):
#    if request.method == 'POST':
#        linkform = LinkForm(request.POST)
#        if linkform.is_valid():
#            print(linkform.cleaned_data)
#            spplink = linkform.cleaned_data['spplink']
#            manlink = spplink
#            request.session['manlink'] = manlink
#            print(request.session.items())
#            services_plus_desc, counter_line_services, pps, turnoff, sreda, tochka, hotspot_points, oattr, address, client, manager, technolog, task_otpm = parse_tr(username, password, spplink)
#            request.session['services_plus_desc'] = services_plus_desc
#            request.session['counter_line_services'] = counter_line_services
#            request.session['pps'] = pps
#            request.session['turnoff'] = turnoff
#            request.session['sreda'] = sreda
#            request.session['tochka'] = tochka
#            request.session['address'] = address
#            request.session['oattr'] = oattr
#            request.session['spplink'] = spplink
#            request.session['client'] = client
#            request.session['manager'] = manager
#            request.session['technolog'] = technolog
#            request.session['task_otpm'] = task_otpm


#            tag_service = []
#            tag_service.append('sppdata')
#            for index_service in range(len(services_plus_desc)):
#                if 'Телефон' in services_plus_desc[index_service]:
#                    tag_service.append('phone')
#                elif 'iTV' in services_plus_desc[index_service]:
#                    tag_service.append('itv')
#                elif 'ЦКС' in services_plus_desc[index_service]:
#                    tag_service.append('cks')
#                elif 'Порт ВЛС' in services_plus_desc[index_service]:
#                    tag_service.append('portvk')
#                elif 'Порт ВМ' in services_plus_desc[index_service]:
#                    tag_service.append('portvm')
#                elif 'ЛВС' in services_plus_desc[index_service]:
#                    tag_service.append('local')
#                elif 'Видеонаблюдение' in services_plus_desc[index_service]:
#                    tag_service.append('video')
#                elif 'HotSpot' in services_plus_desc[index_service]:
#                    if ('премиум +' or 'премиум+') in services_plus_desc[index_service].lower():
#                        premium_plus = True
#                    else:
#                        premium_plus = False
#                    hotspot_users = None
#                    regex_hotspot_users = ['(\d+)посетит', '(\d+) посетит', '(\d+) польз', '(\d+)польз', '(\d+)чел',
#                                           '(\d+) чел']
#                    for regex in regex_hotspot_users:
#                        match_hotspot_users = re.search(regex, services_plus_desc[index_service])
#                        if match_hotspot_users:
#                            hotspot_users = match_hotspot_users.group(1)
#                            break
#
#                    tag_service.append('hotspot')
#                    request.session['hotspot_points'] = hotspot_points
#                    request.session['hotspot_users'] = hotspot_users
#                    request.session['premium_plus'] = premium_plus
#            if counter_line_services == 0:
#                tag_service.append('data')
#            else:
#                if sreda == '1':
#                    tag_service.append('copper')
#                elif sreda == '2' or sreda == '4':
#                    tag_service.append('vols')
#
#            request.session['tag_service'] = tag_service
#            return redirect(tag_service[0])
#            for i in services_plus_desc:
#
#                if 'Телефон' in i:
#                    return redirect('phone')
#                elif 'HotSpot' in i:
#                    if points_hotspot == None:
#                        return redirect('hotspot')
#                    else:
#                        request.session['points_hotspot'] = points_hotspot
#            return redirect('data')

            #context = {'services_plus_desc': services_plus_desc, 'pps': pps, 'turnoff': turnoff, 'oattr': oattr, 'success': success, 'linkform': linkform}
            #return render(request, 'tickets/inputtr.html', context)
#    else:
#        linkform = LinkForm()
        #user = User.objects.get(username=request.user.username)
        #print('user')
        #print(user)
        #user = request.user
        #print(user)
        #passw = user.password
        #lastna = user.last_name
        #print(passw)
        #print(lastna)

#    return render(request, 'tickets/inputtr.html', {'linkform': linkform})

def sppdata(request):
    services_plus_desc = request.session['services_plus_desc']
    client = request.session['client']
    manager = request.session['manager']
    technolog = request.session['technolog']
    task_otpm = request.session['task_otpm']
    address = request.session['address']
    turnoff = request.session['turnoff']
    tag_service = request.session['tag_service']
    tag_service.remove('sppdata')
    next_link = tag_service[0]
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
    if request.method == 'POST':
        copperform = CopperForm(request.POST)

        if copperform.is_valid():
            print(copperform.cleaned_data)
            logic_csw = copperform.cleaned_data['logic_csw']
            port = copperform.cleaned_data['port']
            request.session['logic_csw'] = logic_csw
            request.session['port'] = port
            if logic_csw == True:
                return redirect('csw')
            else:
                return redirect('data')

    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        services_plus_desc = request.session['services_plus_desc']
        turnoff = request.session['turnoff']
        sreda = request.session['sreda']
        tochka = request.session['tochka']
        oattr = request.session['oattr']
        counter_line_services = request.session['counter_line_services']
        spp_link = request.session['spplink']

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')

        for i in range(len(list_switches)):
            switch_ports_var = stash(list_switches[i][0], list_switches[i][1], username, password)
            if switch_ports_var == None:
                pass
            else:
                for port in switch_ports_var.keys():
                    if list_switches[i][10].get(port) == None:
                        switch_ports_var[port].insert(0, '-')
                        switch_ports_var[port].insert(0, '-')
                        list_switches[i][10].update({port: switch_ports_var[port]})
                    else:
                        for from_dev in switch_ports_var[port]:
                            list_switches[i][10][port].append(from_dev)
                list_switches[i][10] = OrderedDict(sorted(list_switches[i][10].items(), key=lambda t: t[0][-2:]))

        request.session['list_switches'] = list_switches
        copperform = CopperForm(initial={'port': 'свободный'})

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
    if request.method == 'POST':
        volsform = VolsForm(request.POST)

        if volsform.is_valid():
            print(volsform.cleaned_data)
            device_client = volsform.cleaned_data['device_client']
            device_pps = volsform.cleaned_data['device_pps']
            logic_csw = volsform.cleaned_data['logic_csw']
            port = volsform.cleaned_data['port']
            speed_port = volsform.cleaned_data['speed_port']
            request.session['device_pps'] = device_pps
            request.session['logic_csw'] = logic_csw
            request.session['port'] = port
            request.session['speed_port'] = speed_port
            try:
                ppr = volsform.cleaned_data['ppr']
            except KeyError:
                ppr = None
            request.session['ppr'] = ppr
            if logic_csw == True:
                device_client = device_client.replace('клиентское оборудование', 'клиентский коммутатор')
                request.session['device_client'] = device_client
                return redirect('csw')
            else:
                request.session['device_client'] = device_client
                return redirect('data')



    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        services_plus_desc = request.session['services_plus_desc']
        turnoff = request.session['turnoff']
        sreda = request.session['sreda']
        tochka = request.session['tochka']
        oattr = request.session['oattr']
        counter_line_services = request.session['counter_line_services']
        spplink = request.session['spplink']
        print('!!!SPPLINK')
        print(spplink)
        regex_link = 'dem_tr\/dem_begin\.php\?dID=(\d+)&tID=(\d+)&trID=(\d+)'
        match_link = re.search(regex_link, spplink)
        dID = match_link.group(1)
        tID = match_link.group(2)
        trID = match_link.group(3)
        print(dID)
        print(tID)
        print(trID)

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')

        for i in range(len(list_switches)):
            switch_ports_var = stash(list_switches[i][0], list_switches[i][1], username, password)
            if switch_ports_var == None:
                pass
            else:
                for port in switch_ports_var.keys():
                    if list_switches[i][10].get(port) == None:
                        switch_ports_var[port].insert(0, '-')
                        switch_ports_var[port].insert(0, '-')
                        list_switches[i][10].update({port: switch_ports_var[port]})
                    else:
                        for from_dev in switch_ports_var[port]:
                            list_switches[i][10][port].append(from_dev)
                list_switches[i][10] = OrderedDict(sorted(list_switches[i][10].items(), key=lambda t: t[0][-2:]))

        request.session['list_switches'] = list_switches


        if sreda == '2':
            volsform = VolsForm(
                initial={'device_pps': 'конвертер 1310 нм, выставить на конвертере режим работы Auto',
                         'device_client': 'конвертер 1550 нм, выставить на конвертере режим работы Auto',
                         'speed_port': 'Auto',
                         'port': 'свободный'}
            )
        elif sreda == '4':
            volsform = VolsForm(
                initial={'device_pps': 'оптический передатчик SFP WDM, до 3 км, 1310 нм',
                         'device_client': 'конвертер 1550 нм, выставить на конвертере режим работы Auto',
                         'speed_port': '100FD'}
            )
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
    if request.method == 'POST':
        wirelessform = WirelessForm(request.POST)

        if wirelessform.is_valid():
            print(wirelessform.cleaned_data)
            access_point = wirelessform.cleaned_data['access_point']
            port = wirelessform.cleaned_data['port']
            logic_csw = wirelessform.cleaned_data['logic_csw']
            try:
                ppr = wirelessform.cleaned_data['ppr']
            except KeyError:
                ppr = None
            request.session['ppr'] = ppr
            request.session['access_point'] = access_point
            request.session['port'] = port
            request.session['logic_csw'] = logic_csw

            if logic_csw == True:
                return redirect('csw')
            else:
                return redirect('data')



    else:
        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']
        pps = request.session['pps']
        #services_plus_desc = request.session['services_plus_desc']
        turnoff = request.session['turnoff']
        sreda = request.session['sreda']
        #tochka = request.session['tochka']
        oattr = request.session['oattr']
        #counter_line_services = request.session['counter_line_services']
        #spp_link = request.session['spplink']

        list_switches = parsingByNodename(pps, username, password)
        if list_switches[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        elif 'No records to display' in list_switches[0]:
            messages.warning(request, 'Нет коммутаторов на узле {}'.format(list_switches[0][22:]))
            return redirect('ortr')

        for i in range(len(list_switches)):
            switch_ports_var = stash(list_switches[i][0], list_switches[i][1], username, password)
            if switch_ports_var == None:
                pass
            else:
                for port in switch_ports_var.keys():
                    if list_switches[i][10].get(port) == None:
                        switch_ports_var[port].insert(0, '-')
                        switch_ports_var[port].insert(0, '-')
                        list_switches[i][10].update({port: switch_ports_var[port]})
                    else:
                        for from_dev in switch_ports_var[port]:
                            list_switches[i][10][port].append(from_dev)
                list_switches[i][10] = OrderedDict(sorted(list_switches[i][10].items(), key=lambda t: t[0][-2:]))

        request.session['list_switches'] = list_switches

        wirelessform = WirelessForm(initial={'port': 'свободный'})
        context = {
            'pps': pps,
            'oattr': oattr,
            'list_switches': list_switches,
            'sreda': sreda,
            'turnoff': turnoff,
            'wirelessform': wirelessform
        }

        return render(request, 'tickets/env.html', context)

def csw(request):
    if request.method == 'POST':
        cswform = CswForm(request.POST)

        if cswform.is_valid():
            model_csw = cswform.cleaned_data['model_csw']
            port_csw = cswform.cleaned_data['port_csw']
            logic_csw_1000 = cswform.cleaned_data['logic_csw_1000']
            request.session['model_csw'] = model_csw
            request.session['port_csw'] = port_csw
            request.session['logic_csw_1000'] = logic_csw_1000
            return redirect('data')
    else:
        sreda = request.session['sreda']
        if sreda == '2' or sreda == '4':
            cswform = CswForm(initial={'model_csw': 'D-Link DGS-1100-06/ME', 'port_csw': '6'})
        else:
            cswform = CswForm(initial={'model_csw': 'D-Link DGS-1100-06/ME', 'port_csw': '5'})

        context = {
            'cswform': cswform
        }
        return render(request, 'tickets/csw.html', context)



def data(request):
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    pps = request.session['pps']
    services_plus_desc = request.session['services_plus_desc']
    turnoff = request.session['turnoff']
    sreda = request.session['sreda']
    tochka = request.session['tochka']
    address = request.session['address']
    oattr = request.session['oattr']


    counter_line_services = request.session['counter_line_services']
    print('!!!!!counter_line_services')
    print(counter_line_services)
    spp_link = request.session['spplink']


    templates = ckb_parse(username, password)

    #request.session['list_switches'] = list_switches
    request.session['templates'] = templates


    try:
        port = request.session['port']
    except KeyError:
        port = None
    try:
        logic_csw = request.session['logic_csw']
    except KeyError:
        logic_csw = None
    try:
        device_pps = request.session['device_pps']
    except KeyError:
        device_pps = None
    try:
        access_point = request.session['access_point']
    except KeyError:
        access_point = None
    try:
        speed_port = request.session['speed_port']
    except KeyError:
        speed_port = None
    try:
        device_client = request.session['device_client']
    except KeyError:
        device_client = None
    try:
        list_switches = request.session['list_switches']
    except KeyError:
        list_switches = None
    try:
        router_shpd = request.session['router_shpd']
    except KeyError:
        router_shpd = None
    try:
        type_shpd = request.session['type_shpd']
    except KeyError:
        type_shpd = None
    try:
        type_cks = request.session['type_cks']
    except KeyError:
        type_cks = None
    try:
        type_portvk = request.session['type_portvk']
    except KeyError:
        type_portvk = None
    try:
        type_portvm = request.session['type_portvm']
    except KeyError:
        type_portvm = None
    try:
        policer_vk = request.session['policer_vk']
    except KeyError:
        policer_vk = None
    try:
        new_vk = request.session['new_vk']
    except KeyError:
        new_vk = None
    try:
        exist_vk = request.session['exist_vk']
    except KeyError:
        exist_vk = None
    try:
        model_csw = request.session['model_csw']
    except KeyError:
        model_csw = None
    try:
        port_csw = request.session['port_csw']
    except KeyError:
        port_csw = None
    try:
        logic_csw_1000 = request.session['logic_csw_1000']
    except KeyError:
        logic_csw_1000 = None
    try:
        pointA = request.session['pointA']
    except KeyError:
        pointA = None
    try:
        pointB = request.session['pointB']
    except KeyError:
        pointB = None
    try:
        policer_cks = request.session['policer_cks']
    except KeyError:
        policer_cks = None
    try:
        policer_vm = request.session['policer_vm']
    except KeyError:
        policer_vm = None
    try:
        new_vm = request.session['new_vm']
    except KeyError:
        new_vm = None
    try:
        exist_vm = request.session['exist_vm']
    except KeyError:
        exist_vm = None
    try:
        vm_inet = request.session['vm_inet']
    except KeyError:
        vm_inet = None
    try:
        hotspot_points = request.session['hotspot_points']
    except KeyError:
        hotspot_points = None
    try:
        hotspot_users = request.session['hotspot_users']
    except KeyError:
        hotspot_users = None
    try:
        exist_client = request.session['exist_client']
    except KeyError:
        exist_client = None

    try:
        camera_number = request.session['camera_number']
    except KeyError:
        camera_number = None
    try:
        camera_model = request.session['camera_model']
    except KeyError:
        camera_model = None
    try:
        voice = request.session['voice']
    except KeyError:
        voice = None
    try:
        deep_archive = request.session['deep_archive']
    except KeyError:
        deep_archive = None
    try:
        camera_place_one = request.session['camera_place_one']
    except KeyError:
        camera_place_one = None
    try:
        camera_place_two = request.session['camera_place_two']
    except KeyError:
        camera_place_two = None
    try:
        vgw = request.session['vgw']
    except KeyError:
        vgw = None
    try:
        channel_vgw = request.session['channel_vgw']
    except KeyError:
        channel_vgw = None
    try:
        ports_vgw = request.session['ports_vgw']
    except KeyError:
        ports_vgw = None
    try:
        local_type = request.session['local_type']
    except KeyError:
        local_type = None
    try:
        local_ports = request.session['local_ports']
    except KeyError:
        local_ports = None
    try:
        sks_poe = request.session['sks_poe']
    except KeyError:
        sks_poe = None
    try:
        sks_router = request.session['sks_router']
    except KeyError:
        sks_router = None
    try:
        lvs_busy = request.session['lvs_busy']
    except KeyError:
        lvs_busy = None
    try:
        lvs_switch = request.session['lvs_switch']
    except KeyError:
        lvs_switch = None
    try:
        ppr = request.session['ppr']
    except KeyError:
        ppr = None
    try:
        type_itv = request.session['type_itv']
    except KeyError:
        type_itv = None
    try:
        cnt_itv = request.session['cnt_itv']
    except KeyError:
        cnt_itv = None




    titles, result_services, result_services_ots, kad = client_new(list_switches, ppr, templates, counter_line_services,
                                                                   services_plus_desc, logic_csw, pps, sreda, port, device_client,
                                                                   device_pps, speed_port, model_csw, port_csw,
                                         logic_csw_1000, pointA, pointB, policer_cks, policer_vk, new_vk, exist_vk, policer_vm,
                                         new_vm, exist_vm, vm_inet, hotspot_points, hotspot_users, exist_client,
                                         camera_number, camera_model, voice, deep_archive, camera_place_one, camera_place_two,
                                         address, vgw, channel_vgw, ports_vgw, local_type, local_ports, sks_poe, sks_router,
                                                                   lvs_busy, lvs_switch, access_point, router_shpd, type_shpd, type_itv, cnt_itv,
                                                                    type_cks, type_portvk, type_portvm)

    userlastname = None
    if request.user.is_authenticated:
        userlastname = request.user.last_name
    now = datetime.datetime.now()
    now = now.strftime("%d.%m.%Y")

    titles = ''.join(titles)
    #titles = titles.replace('\n', '&#13;&#10;')
    result_services = '\n\n\n'.join(result_services)
    #result_services = result_services.replace('\n', '<br />')
    #result_services = titles + '&#13;&#10;' + result_services
    result_services = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + titles + '\n' + result_services
    counter_str_ortr = result_services.count('\n')
    #counter_str_ortr = result_services.count('&#13;&#10;')



    if result_services_ots == None:
        counter_str_ots = 1
    else:
        result_services_ots = '\n\n\n'.join(result_services_ots)
        result_services_ots = 'ОУЗП СПД ' + userlastname + ' ' + now + '\n\n' + result_services_ots
        #result_services_ots = result_services_ots.replace('\n', '&#13;&#10;')
        counter_str_ots = result_services_ots.count('\n')

    request.session['kad'] = kad
    request.session['titles'] = titles
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
    # request.session.flush()
    #list_session_keys = []
    #for key in request.session.keys():
    #    if key.startswith('_'):
    #        pass
    #    else:
    #       list_session_keys.append(key)
    #or key in list_session_keys:
    #   del request.session[key]

    return render(request, 'tickets/data.html', context)




def saved_data(request):
    if request.method == 'POST':
        ortrform = OrtrForm(request.POST)

        if ortrform.is_valid():
            services_plus_desc = request.session['services_plus_desc']
            oattr = request.session['oattr']
            counter_str_ortr = request.session['counter_str_ortr']
            counter_str_ots = request.session['counter_str_ots']
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
            #print(ortrform.cleaned_data['ots_field'])
            #if ortrform.cleaned_data['ots_field'] == None:
            #    pass
            #else:

            #ots_id = request.session['ots_id']
            #ots = OtsTR.objects.get(id=ots_id)
            #ots.ots = ots_field
            #ots.save()

            context = {
                'ticket_k': ticket_k,
                'services_plus_desc': services_plus_desc,
                'oattr': oattr,
                'result_services_ots': result_services_ots,
                #'now': now,
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
        #pps = 'Не требуется' if kad == 'Не требуется' else request.session['pps']
        print('!!!!!kad')
        print(kad)
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

        #now = datetime.datetime.now()

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

        #ortr = OrtrTR()
        ortr.ticket_tr = ticket_tr
        #ortr.title_ortr = titles
        ortr.ortr = result_services
        ortr.ots = result_services_ots
        ortr.save()
        request.session['ortr_id'] = ortr.id
        #if result_services_ots:
        #ots = OtsTR()
        #ots.ticket_tr = ticket_tr
        #ots.ots = result_services_ots
        #ots.save()
        #request.session['ots_id'] = ots.id

        ortrform = OrtrForm(initial={'ortr_field': ortr.ortr, 'ots_field': ortr.ots, 'pps': pps, 'kad': kad})

        context = {
            'ticket_k': ticket_k,
            'services_plus_desc': services_plus_desc,
            'oattr': oattr,
            'result_services_ots': result_services_ots,
            #'now': now,
            'list_switches': list_switches,
            'counter_str_ortr': counter_str_ortr,
            'counter_str_ots': counter_str_ots,
            'ortrform': ortrform

        }

        return render(request, 'tickets/saved_data.html', context)


def edit_tr(request, dID, ticket_spp_id, trID):
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
                #counter_str_ots = 1
                counter_str_ots = ortr.ots.count('\n')
            else:
                #counter_str_ots = ortr.ots.count('\n')
                counter_str_ots = 1
            #print(ortrform.cleaned_data['ots_field'])
            #if ortrform.cleaned_data['ots_field'] == None:
            #    pass
            #else:

            #ots_id = request.session['ots_id']
            #ots = OtsTR.objects.get(id=ots_id)
            #ots.ots = ots_field
            #ots.save()

            context = {
                'services_plus_desc': ticket_tr.services,
                'oattr': ticket_tr.oattr,
                #'result_services_ots': result_services_ots,
                #'now': now,
                #'list_switches': list_switches,
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

        #if ticket_spp.children.filter(ticket_tr=trID):
        ticket_tr = ticket_spp.children.filter(ticket_tr=trID)[0]
        request.session['ticket_tr_id'] = ticket_tr.id

        #if ticket_tr.ortrtr_set.all():
        ortr = ticket_tr.ortrtr_set.all()[0]
        request.session['ortr_id'] = ortr.id

        counter_str_ortr = ortr.ortr.count('\n')
        if ortr.ots:
            counter_str_ots = ortr.ots.count('\n')
        else:
            counter_str_ots = 1


        #try:
        #    list_switches = request.session['list_switches']
        #except KeyError:
        #    list_switches = None




        ortrform = OrtrForm(initial={'ortr_field': ortr.ortr, 'ots_field': ortr.ots, 'pps': ticket_tr.pps, 'kad': ticket_tr.kad})

        context = {
            'services_plus_desc': ticket_tr.services,
            'oattr': ticket_tr.oattr,
            #'result_services_ots': result_services_ots,
            #'now': now,
            #'list_switches': list_switches,
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
            #print(ortrform.cleaned_data['ots_field'])
            #if ortrform.cleaned_data['ots_field'] == None:
            #    pass
            #else:

            #ots_id = request.session['ots_id']
            #ots = OtsTR.objects.get(id=ots_id)
            #ots.ots = ots_field
            #ots.save()

            context = {
                'services_plus_desc': ticket_tr.services,
                'oattr': ticket_tr.oattr,
                #'result_services_ots': result_services_ots,
                #'now': now,
                #'list_switches': list_switches,
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
            ticket_tr.oattr = tr_params['Решение ОТПМ']
            ticket_tr.vID = tr_params['vID']
            ticket_tr.save()
            request.session['ticket_tr_id'] = ticket_tr.id
            print('Сохранили ТР')
            ortr = OrtrTR()
            ortr.ticket_tr = ticket_tr
            ortr.save()
            print('Сохранили ОРТР')
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
                #'result_services_ots': result_services_ots,
                #'now': now,
                #'list_switches': list_switches,
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
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    #Получение страницы с данными о коммутаторе
    spplink = request.session['spplink']
    url = spplink.replace('dem_begin', 'dem_point')
    print(url)
    req_check = requests.get(url, verify=False, auth=HTTPBasicAuth(username, password))
    if req_check.status_code == 200:
        #url = 'https://sss.corp.itmh.ru/dem_tr/dem_point.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)

        ticket_tr_id = request.session['ticket_tr_id']
        ticket_tr = TR.objects.get(id=ticket_tr_id)
        trOTO_AV = ticket_tr.pps
        trOTO_Comm = ticket_tr.kad
        vID = ticket_tr.vID
        print(trOTO_AV)
        print(vID)


        if ticket_tr.ortrtr_set.all():
            ortr = ticket_tr.ortrtr_set.all()[0]

            trOTO_Resolution = ortr.ortr
            trOTS_Resolution = ortr.ots
            print(trOTO_Resolution)

        data = {'trOTO_Resolution': trOTO_Resolution, 'trOTS_Resolution': trOTS_Resolution, 'action': 'saveVariant',
                'trOTO_AV': trOTO_AV, 'trOTO_Comm': trOTO_Comm, 'vID': vID} # {'dID': 111428, 'tID': 130916, 'trID': 54886,
                #'fType': 0, 'vID': 14147, 'noCompress': 1, 'trOTO_Blocked': 1, 'trOTO_AV': 'АВ ЕКБ Учителей 32 П1 Э2',
                #'trOTO_Comm': 'SW037-AR126-31.ekb', 'tr_OTO_Pay': 0, 'tr_OTS_Pay': 0, 'trOTMPK': 0,
                #'loadNewTask': 0}
        #data['NodeName'] = node_name.encode('utf-8')
        req = requests.post(url, verify=False, auth=HTTPBasicAuth(username, password), data=data)
        print('req.status_code send spp')
        print(req.status_code)
        return redirect(spplink)
    else:
        messages.warning(request, 'Нет доступа в ИС Холдинга')
        response = redirect('login_for_service')
        response['Location'] += '?next={}'.format(request.path)
        return response


def flush_session(request):
    list_session_keys = []
    for key in request.session.keys():
        if key.startswith('_'):
            pass
        else:
            list_session_keys.append(key)
    for key in list_session_keys:
        del request.session[key]

    return render(request, 'tickets/flush.html', {'clear': 'clear'})

def flush_session_key(request_request):
    """Данный метод в качестве параметра принимает request, очищает сессию от переменных, полученных при
    проектировании предыдущих ТР, при этом оставляет в сессии переменные относящиеся к пользователю, и возвращает тот же
     request"""
    list_session_keys = []
    for key in request_request.session.keys():
        if key.startswith('_'):
            pass
        else:
            list_session_keys.append(key)
    for key in list_session_keys:
        del request_request.session[key]
    return request_request




def hotspot(request):
    if request.method == 'POST':
        hotspotform = HotspotForm(request.POST)

        if hotspotform.is_valid():
            print(hotspotform.cleaned_data)
            hotspot_points = hotspotform.cleaned_data['hotspot_points']
            hotspot_users = hotspotform.cleaned_data['hotspot_users']
            exist_client = hotspotform.cleaned_data['exist_client']
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
            request.session['exist_client'] = exist_client
            tag_service = request.session['tag_service']
            tag_service.remove('hotspot')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])

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
    if request.method == 'POST':
        phoneform = PhoneForm(request.POST)

        if phoneform.is_valid():
            type_phone = phoneform.cleaned_data['type_phone']
            vgw = phoneform.cleaned_data['vgw']
            channel_vgw = phoneform.cleaned_data['channel_vgw']
            ports_vgw = phoneform.cleaned_data['ports_vgw']
            services_plus_desc = request.session['services_plus_desc']
            tag_service = request.session['tag_service']
            for index_service in range(len(services_plus_desc)):
                if 'Телефон' in services_plus_desc[index_service]:
                    if type_phone == 'ak':
                        services_plus_desc[index_service] += '|'
                        counter_line_services = request.session['counter_line_services']
                        counter_line_services += 1
                        request.session['counter_line_services'] = counter_line_services
                        sreda = request.session['sreda']
                        if sreda == '2' or sreda == '4':
                            if 'vols' in tag_service:
                                pass
                            else:
                                tag_service.insert(1, 'vols')
                        elif sreda == '3':
                            if 'wireless' in tag_service:
                                pass
                            else:
                                tag_service.insert(1, 'wireless')
                        elif sreda == '1':
                            if 'copper' in tag_service:
                                pass
                            else:
                                tag_service.insert(1, 'copper')

                    elif type_phone == 'ap':
                        services_plus_desc[index_service] += '/'
                    elif type_phone == 'ab':
                        services_plus_desc[index_service] += '\\'
            request.session['services_plus_desc'] = services_plus_desc
            request.session['vgw'] = vgw
            request.session['channel_vgw'] = channel_vgw
            request.session['ports_vgw'] = ports_vgw
            tag_service = request.session['tag_service']
            tag_service.remove('phone')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
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

        phoneform = PhoneForm(initial={'type_phone': 's', 'vgw': 'Не требуется', 'channel_vgw': reg_channel_vgw, 'ports_vgw': reg_ports_vgw})
        context = {
            'service_vgw': service_vgw,
            'vats': vats,
            'phoneform': phoneform
        }

        return render(request, 'tickets/phone.html', context)

def local(request):
    if request.method == 'POST':
        localform = LocalForm(request.POST)

        if localform.is_valid():
            local_type = localform.cleaned_data['local_type']
            local_ports = localform.cleaned_data['local_ports']
            request.session['local_type'] = local_type
            request.session['local_ports'] = str(local_ports)
            tag_service = request.session['tag_service']
            tag_service.remove('local')
            request.session['tag_service'] = tag_service
            if local_type == 'СКС':
                return redirect('sks')
            else:
                return redirect('lvs')

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
    if request.method == 'POST':
        sksform = SksForm(request.POST)

        if sksform.is_valid():
            sks_poe = sksform.cleaned_data['sks_poe']
            sks_router = sksform.cleaned_data['sks_router']
            request.session['sks_poe'] = sks_poe
            request.session['sks_router'] = sks_router
            tag_service = request.session['tag_service']
            return redirect(tag_service[0])


    else:
        service_lvs = request.session['service_lvs']
        sksform = SksForm()
        context = {
            'service_lvs': service_lvs,
            'sksform': sksform
        }

        return render(request, 'tickets/sks.html', context)


def lvs(request):
    if request.method == 'POST':
        lvsform = LvsForm(request.POST)

        if lvsform.is_valid():
            lvs_busy = lvsform.cleaned_data['lvs_busy']
            lvs_switch = lvsform.cleaned_data['lvs_switch']
            request.session['lvs_busy'] = lvs_busy
            request.session['lvs_switch'] = lvs_switch
            tag_service = request.session['tag_service']
            return redirect(tag_service[0])


    else:
        service_lvs = request.session['service_lvs']
        lvsform = LvsForm()
        context = {
            'service_lvs': service_lvs,
            'lvsform': lvsform
        }

        return render(request, 'tickets/lvs.html', context)




def itv(request):
    if request.method == 'POST':
        itvform = ItvForm(request.POST)

        if itvform.is_valid():
            type_itv = itvform.cleaned_data['type_itv']
            cnt_itv = itvform.cleaned_data['cnt_itv']
            services_plus_desc = request.session['services_plus_desc']
            tag_service = request.session['tag_service']
            tag_service.remove('itv')
            for index_service in range(len(services_plus_desc)):
                if 'iTV' in services_plus_desc[index_service]:
                    if type_itv == 'novl':
                        services_plus_desc[index_service] = services_plus_desc[index_service][:-1]
                        counter_line_services = request.session['counter_line_services']
                        counter_line_services -= 1
                        request.session['counter_line_services'] = counter_line_services
                        if len(services_plus_desc) == 1:
                            tag_service.pop()
                            tag_service.append('data')
            request.session['type_itv'] = type_itv
            request.session['cnt_itv'] = cnt_itv
            request.session['services_plus_desc'] = services_plus_desc

            print('!!!!tagservice')
            print(tag_service)
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'iTV' in service:
                service_itv = service
                break
        itvform = ItvForm(initial={'type_itv': 'novl'})
        return render(request, 'tickets/itv.html', {'itvform': itvform, 'service_itv': service_itv})

def cks(request):
    if request.method == 'POST':
        cksform = CksForm(request.POST)

        if cksform.is_valid():
            pointA = cksform.cleaned_data['pointA']
            pointB = cksform.cleaned_data['pointB']
            policer_cks = cksform.cleaned_data['policer_cks']
            type_cks = cksform.cleaned_data['type_cks']
            if type_cks == 'trunk':
                request.session['counter_line_services'] = 1

            request.session['pointA'] = pointA
            request.session['pointB'] = pointB
            request.session['policer_cks'] = policer_cks
            request.session['type_cks'] = type_cks
            tag_service = request.session['tag_service']
            tag_service.remove('cks')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
        services_cks = []
        for service in services_plus_desc:
            if 'ЦКС' in service:
                services_cks.append(service)

        user = User.objects.get(username=request.user.username)
        credent = cache.get(user)
        username = credent['username']
        password = credent['password']



        tochka = request.session['tochka']
        list_strok = match_cks(tochka, username, password)
        if list_strok[0] == 'Access denied':
            messages.warning(request, 'Нет доступа в ИС Холдинга')
            response = redirect('login_for_service')
            response['Location'] += '?next={}'.format(request.path)
            return response
        else:
            if len(list_strok) == 1:
                pointsCKS = list_strok[0].split('-')
                pointA = pointsCKS[0]
                pointB = pointsCKS[1]
                cksform = CksForm(initial={'pointA': pointA, 'pointB': pointB})
                return render(request, 'tickets/cks.html', {'cksform': cksform, 'services_cks': services_cks})
            else:
                cksform = CksForm()
                return render(request, 'tickets/cks.html', {'cksform': cksform, 'list_strok': list_strok, 'services_cks': services_cks})


def shpd(request):
    if request.method == 'POST':
        shpdform = ShpdForm(request.POST)

        if shpdform.is_valid():
            router_shpd = shpdform.cleaned_data['router']
            type_shpd = shpdform.cleaned_data['type_shpd']
            if type_shpd == 'trunk':
                request.session['counter_line_services'] = 1
            request.session['router_shpd'] = router_shpd
            request.session['type_shpd'] = type_shpd
            tag_service = request.session['tag_service']
            tag_service.remove('shpd')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
        services_shpd = []
        for service in services_plus_desc:
            if 'Интернет, DHCP' in service or 'Интернет, блок Адресов Сети Интернет' in service:
                services_shpd.append(service)
        shpdform = ShpdForm(initial={'shpd': 'access'})
        return render(request, 'tickets/shpd.html', {'shpdform': shpdform, 'services_shpd': services_shpd})



def portvk(request):
    if request.method == 'POST':
        portvkform = PortVKForm(request.POST)

        if portvkform.is_valid():
            new_vk = portvkform.cleaned_data['new_vk']
            exist_vk = '"{}"'.format(portvkform.cleaned_data['exist_vk'])
            policer_vk = portvkform.cleaned_data['policer_vk']
            type_portvk = portvkform.cleaned_data['type_portvk']
            if type_portvk == 'trunk':
                request.session['counter_line_services'] = 1


            request.session['policer_vk'] = policer_vk
            request.session['new_vk'] = new_vk
            request.session['exist_vk'] = exist_vk
            request.session['type_portvk'] = type_portvk
            tag_service = request.session['tag_service']
            tag_service.remove('portvk')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
        services_vk = []
        for service in services_plus_desc:
            if 'Порт ВЛС' in service:
                services_vk.append(service)
        portvkform = PortVKForm()
        return render(request, 'tickets/portvk.html', {'portvkform': portvkform, 'services_vk': services_vk})

def portvm(request):
    if request.method == 'POST':
        portvmform = PortVMForm(request.POST)

        if portvmform.is_valid():
            new_vm = portvmform.cleaned_data['new_vm']
            exist_vm = '"{}"'.format(portvmform.cleaned_data['exist_vm'])
            policer_vm = portvmform.cleaned_data['policer_vm']
            vm_inet = portvmform.cleaned_data['vm_inet']
            type_portvm = portvmform.cleaned_data['type_portvm']
            if type_portvm == 'trunk':
                request.session['counter_line_services'] = 1

            request.session['policer_vm'] = policer_vm
            request.session['new_vm'] = new_vm
            request.session['exist_vm'] = exist_vm
            request.session['vm_inet'] = vm_inet
            request.session['type_portvm'] = type_portvm
            tag_service = request.session['tag_service']
            tag_service.remove('portvm')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])


    else:
        services_plus_desc = request.session['services_plus_desc']
        services_vm = []
        for service in services_plus_desc:
            if 'Порт ВМ' in service:
                services_vm.append(service)
        portvmform = PortVMForm()
        return render(request, 'tickets/portvm.html', {'portvmform': portvmform, 'services_vm': services_vm})


def video(request):
    if request.method == 'POST':
        videoform = VideoForm(request.POST)

        if videoform.is_valid():
            print(videoform.cleaned_data)
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
            tag_service.remove('video')
            request.session['tag_service'] = tag_service
            return redirect(tag_service[0])

    else:
        services_plus_desc = request.session['services_plus_desc']
        for service in services_plus_desc:
            if 'Видеонаблюдение' in service:
                service_video = service
                request.session['service_video'] = service_video
                break
        task_otpm = request.session['task_otpm']
        videoform = VideoForm() #initial={'hotspot_points': hotspot_points, 'hotspot_users': hotspot_users})
        context = {
            'service_video': service_video,
            'videoform': videoform,
            'task_otpm': task_otpm
        }
        return render(request, 'tickets/video.html', context)

def get_contract_id(login, password, contract):
    url = f'https://cis.corp.itmh.ru/doc/crm/contract_ajax.ashx?term={contract}'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    contract_list = req.json()
    print(contract_list)
    if len(contract_list) > 1:
        pass
    elif len(contract_list) == 0:
        pass
    else:
        contract_id = contract_list[0].get('id')
        print(contract_id)
    return contract_id

def get_contract_resources(login, password, contract_id):
    url = f'https://cis.corp.itmh.ru/doc/CRM/contract.aspx?contract={contract_id}'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    soup = BeautifulSoup(req.content.decode('utf-8'), "html.parser")
    table = soup.find('table', id="ctl00_middle_Table_ONO")
    rows_tr = table.find_all('tr')
    ono = []
    for index, element_rows_tr in enumerate(rows_tr):
        ono_inner = []
        for element_rows_td in element_rows_tr.find_all('td'):
            ono_inner.append(element_rows_td.text)
        print(ono_inner)
        ono_inner.pop(5)
        ono_inner.pop(2)
        ono.append(ono_inner)
    return ono

@cache_check
def get_resources(request):
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    if request.method == 'POST':
        print('!!!!req_con')
        print(request.POST)
        contractform = ContractForm(request.POST)
        if contractform.is_valid():
            print(contractform.cleaned_data)
            contract = contractform.cleaned_data['contract']
            contract_id = get_contract_id(username, password, contract)
            ono = get_contract_resources(username, password, contract_id)
            request.session['ono'] = ono
            request.session['contract'] = contract
            if ono:
                #return redirect('show_resources')
                return redirect('test_formset')
            else:
                messages.warning(request, 'Договора не найдено')
                return redirect('get_resources')
    else:
        contractform = ContractForm()

    return render(request, 'tickets/contract.html', {'contractform': contractform})

def show_resources(request):
    ono = request.session['selected_ono']
    contract = request.session['contract']
    context = {
        'ono': ono,
        'contract': contract
    }
    return render(request, 'tickets/show_resources.html', context)


def _replace_wda_wds(device):
    replace_wda_wds = device.split('-')
    replace_wda_wds[0] = replace_wda_wds[0].replace('WDA', 'WDS')
    replace_wda_wds.pop(1)
    device = '-'.join(replace_wda_wds)
    return device


def _get_chain(login, password, device, max_level):
    if device.startswith('WDA'):
        device = _replace_wda_wds(device)
        print('!!!dev')
        print(device)
    elif device.startswith('WFA'):
        replace_wfa_wfs = device.split('-')
        replace_wfa_wfs[0] = replace_wfa_wfs[0].replace('WFA', 'WFS')
        replace_wfa_wfs.pop(1)
        device = '-'.join(replace_wfa_wfs)

    url = f'https://mon.itss.mirasystem.net/mp/index.py/chain_update?hostname={device}'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    chains = req.json()
    vgw_on_node = []
    uplink = None
    temp_chains2 = []
    index_uplink = 0
    for chain in chains:
        print('!!chain')
        print(chain)
        if device.startswith('SW') or device.startswith('CSW') or device.startswith('WDS'):
            if 'VGW' in chain.get('host_name'):
                vgw_on_node.append(chain.get('host_name'))

        if device in chain.get('title'):
            var_node = chain.get('alias')
            temp_chains2 = chain.get('title').split('\nLink')

            #print(temp_chains2)
            for i in temp_chains2:
                #print(i)
                if device.startswith('CSW') or device.startswith('WDS') or device.startswith('WFS'):
                    if f'-{device}' in i:     #  для всех случаев подключения CSW, WDS, WFS
                        preuplink = i.split(f'-{device}')
                        preuplink = preuplink[0]
                        match_uplink = re.search('_(\S+?)_(\S+)', preuplink)
                        uplink_host = match_uplink.group(1)
                        uplink_port = match_uplink.group(2)
                        if uplink_host == chain.get('host_name') and chain.get('level') < max_level:
                            print('!!up')
                            print(uplink_host)
                            print(uplink_port)
                            max_level = chain.get('level')

                            if 'thernet' in uplink_port:
                                uplink_port = uplink_port.replace('_', '/')
                            else:
                                uplink_port = uplink_port.replace('_', ' ')
                            uplink = uplink_host + ' ' + uplink_port
                            node_mon = var_node
                            #index_uplink = 1
                        else:
                            pass
                    elif device in i and 'WDA' in i:    # исключение только для случая, когда CSW подключен от WDA
                        link = i.split('-WDA')
                        uplink = 'WDA' + link[1].replace('_', ' ').replace('\n', '')
                        print('!!!wdauplink')
                        print(uplink)
                        node_mon = var_node

                else:
                    if f'_{device}' in i:
                        node_mon = var_node

    return node_mon, uplink, vgw_on_node, max_level

@cache_check
def get_chain(request):
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    if request.method == 'POST':
        chainform = ChainForm(request.POST)
        if chainform.is_valid():
            print(chainform.cleaned_data)
            chain_device = chainform.cleaned_data['chain_device']
            max_level = 20
            node_mon, uplink, vgw_chains, max_level = _get_chain(username, password, chain_device, max_level)
            all_chain = []
            all_chain.append(uplink)
            while uplink.startswith('CSW') or uplink.startswith('WDA'):
                next_chain_device = uplink.split()
                all_chain.pop()
                if uplink.startswith('CSW') and chain_device.startswith('WDA'):
                    all_chain.append(_replace_wda_wds(chain_device))
                all_chain.append(next_chain_device[0])
                if uplink.startswith('WDA'):
                    all_chain.append(_replace_wda_wds(next_chain_device[0]))
                node_mon, uplink, vgw_chains, max_level = _get_chain(username, password, next_chain_device[0], max_level)
                all_chain.append(uplink)
            request.session['node_mon'] = node_mon
            request.session['uplink'] = all_chain
            request.session['vgw_chains'] = vgw_chains
            if node_mon:
                return redirect('show_chains')
            else:
                messages.warning(request, 'не найдено')
                return redirect('get_chain')
    else:
        chainform = ChainForm()

    return render(request, 'tickets/get_chain.html', {'chainform': chainform})


def show_chains(request):
    node_mon = request.session['node_mon']
    uplink = request.session['uplink']
    vgw_chains = request.session['vgw_chains']
    context = {
        'node_mon': node_mon,
        'uplink': uplink,
        'vgw_chains': vgw_chains
    }
    return render(request, 'tickets/chain.html', context)


def parse_tr(login, password, url):
    # Получение данных со страницы Тех решения
    #url = input('Ссылка на Тех.решение: ')
    url = url.replace('dem_begin', 'dem_point')
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 200:
        parsed = req.content.decode('utf-8')

        # Получение данных среды передачи с блока "ОТПМ"
        sreda = None
        regex_env = 'Время на реализацию, дней</td>\r\n<td colspan="2">\d</td>\r\n</tr>\r\n\r\n\r\n\r\n\r\n\r\n<tr av_req="1">\r\n<td colspan="3" align="left">\r\n(.+)</td>\r\n</tr>\r\n\r\n\r\n\r\n<tr obt_req'
        match_env = re.search(regex_env, parsed, flags=re.DOTALL)
        try:
            oattr = match_env.group(1)
            oattr = oattr.replace('<br />', '').replace('&quot;', '"').replace('&amp;', '&')
            if ((not 'ОК' in oattr) and ('БС ' in oattr)) or (
                    (not 'ОК' in oattr) and ('радио' in oattr)) or (
                    (not 'ОК' in oattr) and ('радиоканал' in oattr)) or ((not 'ОК' in oattr) and ('антенну' in oattr)):
                sreda = '3'
                print('Среда передачи:  Беспроводная среда')
            elif ('Alpha' in oattr) or (('ОК-1' in oattr) and (not 'ОК-16' in oattr)):
                sreda = '4'
                print('Среда передачи: FTTH')
            elif ('ОВ' in oattr) or ('ОК' in oattr) or ('ВОЛС' in oattr) or ('волокно' in oattr) or (
                    'ОР ' in oattr) or ('ОР№' in oattr) or ('сущ.ОМ' in oattr) or ('оптическ' in oattr):
                sreda = '2'
                print('Среда передачи: ВОЛС')
            else:
                sreda = '1'
                print('Среда передачи: UTP')
        except AttributeError:
            sreda = '1'
            oattr = None
            print('Среда передачи: UTP')

        # Получение данных с блока "Перечень требуемых услуг"
        services_plus_desc = []
        services = []
        hotspot_points = None
        regex_serv = "Service_ID_\d+\'\>\r\n(?:\t)+<TD>(.+)</TD>\r\n(?:\t)+<TD>(.+)</TD>"  # "услуга" - group(1) и "описание" - group(2)
        for service in re.finditer(regex_serv, parsed):
            if service.group(1) in ['Сопровождение ИС', 'Другое']:
                pass
            # проверка на наличие в списке услуг нескольких строк с одной услугой
            elif service.group(1) in services and service.group(1) in ['Телефон', 'ЛВС', 'HotSpot', 'Видеонаблюдение']:
                for i in range(len(services_plus_desc)):
                    if service.group(1) in services_plus_desc[i]:
                        services_plus_desc[i] += ' {}'.format(service.group(2))
            else:
                one_service_plus_des = ' '.join(service.groups())
                services.append(service.group(1))
                services_plus_desc.append(one_service_plus_des)

        for i in range(len(services_plus_desc)):
            services_plus_desc[i] = services_plus_desc[i].replace('&quot;', '"')
            print('Услуга:  {}'.format(
                services_plus_desc[i]))



        # проходим по списку услуг чтобы определить количество организуемых линий от СПД и в той услуге, где требуется
        # добавляем спец. символ
        for index_service in range(len(services_plus_desc)):
            if 'Интернет, блок Адресов Сети Интернет' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
                replace_index = services_plus_desc[index_service]
                services_plus_desc.remove(replace_index)
                services_plus_desc.insert(0, replace_index)
            elif 'Интернет, DHCP' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
                replace_index = services_plus_desc[index_service]
                services_plus_desc.remove(replace_index)
                services_plus_desc.insert(0, replace_index)
            elif 'iTV' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
            elif 'ЦКС' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
            elif 'Порт ВЛС' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
            elif 'Порт ВМ' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
            elif 'HotSpot' in services_plus_desc[index_service]:
                services_plus_desc[index_service] += '|'
                regex_hotspot_point = ['(\d+)станц', '(\d+) станц', '(\d+) точ', '(\d+)точ', '(\d+)антен', '(\d+) антен']
                for regex in regex_hotspot_point:
                    match_hotspot_point = re.search(regex, services_plus_desc[index_service])
                    if match_hotspot_point:
                        hotspot_points = match_hotspot_point.group(1)
                        break

        counter_line_services = 0
        for i in services_plus_desc:
            while i.endswith('|'):
                counter_line_services += 1
                i = i[:-1]

        pps = None
        turnoff = None

        #if counter_line_services > 0:
        # Получение данных с блока "Узел подключения клиента"
        # Разделение сделано, т.к. для обычного ТР и упрощенки разный regex
        match_AB = None
        regex_AB = 'Изменить</span></div>\r\n</td>\r\n<td colspan="2">\r\n\t(.+) &'
        match_AB = re.search(regex_AB, parsed)
        if match_AB is None:
            regex_AB = 'Изменить</a></div>\r\n</td>\r\n<td colspan="2">\r\n\t(.+) &'
            match_AB = re.search(regex_AB, parsed)
            if match_AB is None:
                pps = 'Не выбран'
            else:
                pps = match_AB.group(1)
                pps = pps.replace('&quot;', '"')
        else:
            pps = match_AB.group(1)
            pps = pps.replace('&quot;', '"')


        # print(pps)

        # Получение данных с блока "Отключение"
        match_turnoff = None
        regex_turnoff = 'INPUT  disabled=\'disabled\' id=\'trTurnOff'
        match_turnoff = re.search(regex_turnoff, parsed)
        if match_turnoff is None:
            turnoff = True
            print('Отключение:  Внимание! Требуется отключение')
        else:
            turnoff = False
            print('Отключение:  Отключение не требуется')



        tochka = []
        regex_tochka = 'dID=(\d+)&tID=(\d+)&trID'
        match_tochka = re.search(regex_tochka, parsed)
        id1 = match_tochka.group(1)
        id2 = match_tochka.group(2)
        tochka.append(id1)
        tochka.append(id2)

        url = 'https://sss.corp.itmh.ru/dem_tr/dem_point_panel.php?dID={}&tID={}'.format(id1, id2)
        req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
        parsed = req.content.decode('utf-8')
        regex_address = "\({},{}\)'>&nbsp;(.+?)&nbsp;</a>".format(id1, id2)
        match_address = re.search(regex_address, parsed)
        address = match_address.group(1)
        address = address.replace(', д.', ' ')


        url = 'https://sss.corp.itmh.ru/dem_tr/dem_adv.php?dID={}'.format(id1)
        req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
        parsed = req.content.decode('utf-8')
        regex_client = 'Клиент\r\n            </td>\r\n            <td colspan="3">\r\n(.+)</td>'
        match_client = re.search(regex_client, parsed)
        client = match_client.group(1)
        client = ' '.join(client.split())
        client = client.replace('&quot;', '"')
        print(client)
        regex_manager = 'Менеджер клиента            </td>\r\n            <td align="left" colspan="3">\r\n(.+)</td>'
        match_manager = re.search(regex_manager, parsed)
        try:
            manager = match_manager.group(1)
            manager = ' '.join(manager.split())
            print(manager)
        except AttributeError:
            manager = None
        regex_technolog = 'Технологи\r\n            </td>\r\n            <td align="left" colspan="3">\r\n(.+)</td>'
        match_technolog = re.search(regex_technolog, parsed)
        technolog = match_technolog.group(1)
        technolog = ' '.join(technolog.split())
        print(technolog)

        regex_task_otpm = 'Задача в ОТПМ\r\n(?:\s+)</td>\r\n(?:\s+)<td colspan="3" valign="top">(.+)</td>'
        match_task_otpm = re.search(regex_task_otpm, parsed, flags=re.DOTALL)
        task_otpm = match_task_otpm.group(1)
        task_otpm = task_otpm[:task_otpm.find('</td>')]
        task_otpm = ' '.join(task_otpm.split())
        print(task_otpm)

        data_sss = []
        data_sss.append(services_plus_desc)
        data_sss.append(counter_line_services)
        data_sss.append(pps)
        data_sss.append(turnoff)
        data_sss.append(sreda)
        data_sss.append(tochka)
        data_sss.append(hotspot_points)
        data_sss.append(oattr)
        data_sss.append(address)
        data_sss.append(client)
        data_sss.append(manager)
        data_sss.append(technolog)
        data_sss.append(task_otpm)

        return data_sss
    else:
        data_sss = []
        data_sss.append('Access denied')
        return data_sss


def parsingByNodename(node_name, login, password):

    #Получение страницы с данными о коммутаторе
    url = 'https://cis.corp.itmh.ru/stu/NetSwitch/SearchNetSwitchProxy'
    data = {'IncludeDeleted': 'false', 'IncludeDisabled': 'true', 'HideFilterPane': 'false'}
    data['NodeName'] = node_name.encode('utf-8')
    req = requests.post(url, verify=False, auth=HTTPBasicAuth(login, password), data=data)
    print('!!!!!')
    print('req.status_code')
    print(req.status_code)
    if req.status_code == 200:
        switch = req.content.decode('utf-8')
        if 'No records to display.' in switch:
            list_switches = []
            list_switches.append('No records to display {}'.format(node_name))
            return list_switches
        else:
            # Получение данных о названии и модели всех устройств на узле связи
            regex_name_model = '\"netswitch-name\\\\\" >\\\\r\\\\n\s+?(\S+?[ekb|ntg|kur])\\\\r\\\\n\s+?</a>\\\\r\\\\n\s+?\\\\r\\\\n</td><td>(.+?)</td><td>\\\\r\\\\n\s+?<a href=\\\\\"/stu/Node'
            match_name_model = re.findall(regex_name_model, switch)

            # Выявление индексов устройств с признаком SW и CSW
            clear_name_model = []
            clear_index = []
            for i in range(len(match_name_model)):
                if match_name_model[i][0][:2] == 'CSW' or match_name_model[i][0][:2] == 'SW':
                    clear_index.append(i)
                    clear_name_model.append(match_name_model[i])

            # в regex добавлены знаки ?, чтобы отключить жадность. в выводе match список кортежей

            # Получение данных об узле КАД
            regex_node = 'netswitch-nodeName\\\\\">\\\\r\\\\n\s+(.+?[АВ|КК|УА|РУА])\\\\r\\\\n '
            match_node = re.findall(regex_node, switch)
            # в regex добавлены знаки ?, чтобы отключить жадность. в выводе match список узлов - строк

            # Получение данных об ip-адресе КАД
            regex_ip = '\"telnet://([0-9.]+)\\\\'
            match_ip = re.findall(regex_ip, switch)
            clear_ip = []
            for i in clear_index:
                clear_ip.append(match_ip[i])

            # в выводе match список ip - строк

            # Получение данных о магистральном порте КАД
            regex_uplink = 'uplinks-count=\\\\\"\d+\\\\\">\\\\r\\\\n(?:\\\\t)+ (.+?)\\\\r\\\\n(?:\\\\t)+ </span>'
            match_uplink = re.findall(regex_uplink, switch)
            clear_uplink = []
            for i in clear_index:
                clear_uplink.append(match_uplink[i])

            regex_status_desc = '(ВКЛ|ВЫКЛ)</td><td>(.+?)</td>'
            match_status_desc = re.findall(regex_status_desc, switch)
            clear_status_desc = []
            for i in clear_index:
                clear_status_desc.append(match_status_desc[i])
            print('!!!!!')
            print('clear_status_desc')
            print(clear_status_desc)

            # в выводе match список uplink - строк

            # Получение данных об id КАД для формирования ссылки на страницу портов КАД
            regex_switch_id = 'span class=\\\\\"netSwitchPorts\\\\\" switch-id=\\\\\"(\d+)\\\\'
            match_switch_id = re.findall(regex_switch_id, switch)
            list_ports = []
            clear_switch_id = []

            configport_switches = []

            for i in clear_index:
                clear_switch_id.append(match_switch_id[i])
            for i in clear_switch_id:
                ports = {}

                url_switch_id = 'https://cis.corp.itmh.ru/stu/Switch/Details/' + i
                req_switch_id = requests.get(url_switch_id, verify=False, auth=HTTPBasicAuth(login, password))
                switch_id = req_switch_id.content.decode('utf-8')

                regex_total_ports = 'for=\"TotalPorts\">(\d+)<'
                match_total_ports = re.search(regex_total_ports, switch_id)
                ports['Всего портов'] = match_total_ports.group(1)

                #regex_broken_ports = 'for=\"BrokenPorts\">(\d+)<'
                #match_broken_ports = re.search(regex_broken_ports, switch_id)
                #ports['Неисправных'] = match_broken_ports.group(1)

                regex_client_ports = 'for=\"ClientCableUsedPorts\">(\d+)<'
                match_client_ports = re.search(regex_client_ports, switch_id)
                ports['Занятых клиентами'] = match_client_ports.group(1)

                regex_link_ports = 'for=\"LinkUsedPorts\">(\d+)<'
                match_link_ports = re.search(regex_link_ports, switch_id)
                ports['Занятых линками'] = match_link_ports.group(1)

                #regex_zombi_ports = 'for=\"ZombieContractPorts\">(\d+)<'
                #match_zombi_ports = re.search(regex_zombi_ports, switch_id)
                #ports['Зомби'] = match_zombi_ports.group(1)

                #regex_free_ports = 'for=\"FreePorts\">(\d+)<'
                #match_free_ports = re.search(regex_free_ports, switch_id)
                #ports['Свободные'] = match_free_ports.group(1)

                regex_avail_ports = 'for=\"AvailablePorts\">(\d+)<'
                match_avail_ports = re.search(regex_avail_ports, switch_id)
                ports['Доступные'] = match_avail_ports.group(1)
                list_ports.append(ports)


                configport_switch = {}
                for page in range(1, 4):
                    url_port_config = 'https://cis.corp.itmh.ru/stu/NetSwitch/PortConfigs?switchId=' + i + '&PortGonfigsGrid-page=' + str(
                        page)
                    req_port_config = requests.get(url_port_config, verify=False, auth=HTTPBasicAuth(login, password))
                    port_config = req_port_config.content.decode('utf-8')
                    regex_port_config = '<td>(.+)</td><td>(.+)</td><td>(.+)</td><td>(?:.*)</td><td style="text-align:left">'
                    match_port_config = re.finditer(regex_port_config, port_config)  # flags=re.DOTALL
                    for port in match_port_config:
                        configport_switch[port.group(2)] = [port.group(1), port.group(3)]
                configport_switches.append(configport_switch)



            list_switches = []
            for i in range(len(clear_name_model)):
                #list_switches.append([clear_name_model[i][0], clear_name_model[i][1], match_node[i], clear_ip[i], clear_uplink[i], list_ports[i]])
                list_switches.append(
                    [clear_name_model[i][0], clear_name_model[i][1], clear_ip[i], clear_uplink[i], clear_status_desc[i][0], clear_status_desc[i][1],
                     list_ports[i]['Всего портов'], list_ports[i]['Занятых клиентами'], list_ports[i]['Занятых линками'], list_ports[i]['Доступные'], configport_switches[i]])

            print('!!!!')
            print('list_switches')
            print(list_switches)
            return list_switches
    else:
        list_switches = []
        list_switches.append('Access denied')
        return list_switches







def ckb_parse(login, password):
    templates = {}
    url = 'https://ckb.itmh.ru/login.action?os_destination=%2Fpages%2Fviewpage.action%3FpageId%3D323312207&permissionViolation=true'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    soup = BeautifulSoup(req.content.decode('utf-8'), "html.parser")
    search = soup.find_all('pre', {'class': 'syntaxhighlighter-pre'})
    for item in search:
        regex = '(.+)'
        match = re.search(regex, item.text)
        title = match.group(1)
        templates[title] = item.text
    return templates

#@login_required(login_url='login/', redirect_field_name='next')
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
        for i in search:
            list_search.append(i[0])
        print(list_search)
        spp_proc_wait = SPP.objects.filter(Q(process=True) | Q(wait=True))
        list_spp_proc_wait = []
        for i in spp_proc_wait:
            list_spp_proc_wait.append(i.ticket_k)
        print(list_spp_proc_wait)
        list_search_rem = []
        for i in list_spp_proc_wait:
            for index_j in range(len(list_search)):
                if i in list_search[index_j]:
                    list_search_rem.append(index_j)
        print(list_search_rem)
        search[:] = [x for i, x in enumerate(search) if i not in list_search_rem]
        spp_process = SPP.objects.filter(process=True)

        return render(request, 'tickets/ortr.html', {'search': search, 'spp_process':spp_process})


def primer_get_tr(request, ticket_tr, ticket_id):
    services_one_tr = []
    one_tr = TR.objects.get(ticket_tr=ticket_tr, id=ticket_id)
    for item in one_tr.servicestr_set.all():
        services_one_tr.append(item.service)
    data_one_tr = one_tr.datatr_set.get()
    ortr_one_tr = one_tr.ortrtr_set.first() #first вместо get, т.к. если записи нет, то будет исключение DoesNotExist
    context = {
        'one_tr': one_tr,
        'services_one_tr': services_one_tr,
        'data_one_tr': data_one_tr,
        'ortr_one_tr': ortr_one_tr
    }

    return render(request, 'tickets/tr.html', context=context)

from django.core.exceptions import ObjectDoesNotExist

@cache_check
def add_spp(request, dID):
    '''должна принимать параметром номер заявки, парсить и добавлять в базу заявку. Сможет работать отдельно от заявок
    в пуле ОРТР, просто вводим урл и номер заявки и она добавляется в бд. А кнопка взять в работу будет ссылкой на этот урл,
    но тогда не получится добавлять в базу время, когда заявка попала в пул(надо подумать учитывать это или нет)
    вызывает for_spp_view, for_tr_view'''
    user = User.objects.get(username=request.user.username)
    credent = cache.get(user)
    username = credent['username']
    password = credent['password']
    print('add_spp get username')
    print(username)
    print(password)
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
            #exist_dID = len(SPP.objects.filter(dID=dID))
            #if exist_dID:
            #    version = exist_dID + 1
            #else:
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
            # request.session['ticket_spp_id'] = ticket_spp.id
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
                #if exist_dID:
                version = exist_dID + 1
                #else:
                #    version = 1

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
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.process = False
    current_ticket_spp.save()
    messages.success(request, 'Работа по заявке {} завершена'.format(current_ticket_spp.ticket_k))
    return redirect('ortr')


def remove_spp_wait(request, ticket_spp_id):
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.wait = False
    #current_ticket_spp. = False
    current_ticket_spp.save()
    messages.success(request, 'Заявка {} возвращена из ожидания'.format(current_ticket_spp.ticket_k))
    return redirect('ortr')

def add_spp_wait(request, ticket_spp_id):
    current_ticket_spp = SPP.objects.get(id=ticket_spp_id)
    current_ticket_spp.wait = True
    current_ticket_spp.process = False
    current_ticket_spp.save()
    messages.success(request, 'Заявка {} перемещена в ожидание'.format(current_ticket_spp.ticket_k))
    return redirect('wait')


def spp_view_save(request, dID, ticket_spp_id):
    request.session['ticket_spp_id'] = ticket_spp_id
    request.session['dID'] = dID
    current_ticket_spp = get_object_or_404(SPP, dID=dID, id=ticket_spp_id)
    return render(request, 'tickets/spp_view_save.html', {'current_ticket_spp': current_ticket_spp})

@cache_check
def spp_view(request, dID):
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

def for_spp_view(login, password, dID):
    spp_params = {}
    sostav = []
    url = 'https://sss.corp.itmh.ru/dem_tr/dem_adv.php?dID={}'.format(dID)
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 200:
        soup = BeautifulSoup(req.content.decode('utf-8'), "html.parser")
        search = soup.find_all('tr')
        for i in search:
            if 'Заказчик' in i.find_all('td')[0].text:
                customer = ''.join(i.find_all('td')[1].text.split())
                print('!!!!customer')
                print(customer)
                if 'Проектно-технологическийотдел' in customer or 'ОТПМ' in customer:
                    spp_params['Тип заявки'] = 'ПТО'
                else:
                    spp_params['Тип заявки'] = 'Коммерческая'
            elif 'Заявка К' in i.find_all('td')[0].text:
                spp_params['Заявка К'] = ''.join(i.find_all('td')[1].text.split())
            elif 'Менеджер клиента' in i.find_all('td')[0].text:
                spp_params['Менеджер'] = i.find_all('td')[1].text
            elif 'Клиент' in i.find_all('td')[0].text:
                spp_params['Клиент'] = i.find_all('td')[1].text
            elif 'Разработка схем/карт' in i.find_all('td')[0].text:
                spp_params['Менеджер'] = i.find_all('td')[1].text
            elif 'Технологи' in i.find_all('td')[0].text:
                spp_params['Технолог'] = i.find_all('td')[1].text
            elif 'Задача в ОТПМ' in i.find_all('td')[0].text:
                spp_params['Задача в ОТПМ'] = i.find_all('td')[1].text
            elif 'ТР по упрощенной схеме' in i.find_all('td')[0].text:
                spp_params['ТР по упрощенной схеме'] = i.find_all('td')[1].text
            elif 'Перечень' in i.find_all('td')[0].text:
                services = i.find_all('td')[1].text
                services = services[::-1]
                services = services[:services.index('еинасипО')]
                services = services[::-1]
                services = services.split('\n\n')
                services.pop(0)
                spp_params['Перечень требуемых услуг'] = services
            elif 'Состав Заявки ТР' in i.find_all('td')[0].text:
                for links in i.find_all('td')[1].find_all('a'):
                    all_link = {}
                    if 'trID' in links.get('href'):
                        regex = 'tID=(\d+)&trID=(\d+)'
                        match_href = re.search(regex, links.get('href'))
                        total_link = [match_href.group(1), match_href.group(2)]
                    else:
                        total_link = None
                    all_link[links.text] = total_link
                    sostav.append(all_link)
                spp_params['Состав Заявки ТР'] = sostav
            elif 'Примечание' in i.find_all('td')[0].text:
                spp_params['Примечание'] = i.find_all('td')[1].text
        return spp_params
    else:
        spp_params['Access denied'] = 'Access denied'
        return spp_params




#@login_required(login_url='tickets/login/')
@cache_check
def add_tr(request, dID, tID, trID):
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
        ticket_tr.oattr = tr_params['Решение ОТПМ']
        #ticket_tr.tr_OTO_Pay = tr_params['tr_OTO_Pay']
        #ticket_tr.tr_OTS_Pay = tr_params['tr_OTS_Pay']
        #ticket_tr.trOTMPType = tr_params['trOTMPType']
        #ticket_tr.trArticle = tr_params['trArticle']
        ticket_tr.vID = tr_params['vID']
        ticket_tr.save()
        request.session['ticket_tr_id'] = ticket_tr.id
        print(request.GET)

        return redirect('project_tr', dID, tID, trID)


def tr_view_save(request, dID, ticket_spp_id, trID):
    #request.session['ticket_spp_id'] = ticket_spp_id
    #request.session['dID'] = dID
    #current_ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)

    #current_ticket_tr = TR.objects.get(ticket_tr=ticket_tr, ticket_k__id=ticket_spp_id)

    #ticket_spp_id = request.session['ticket_spp_id']
    #dID = request.session['dID']
    ticket_spp = SPP.objects.get(dID=dID, id=ticket_spp_id)

    # if ticket_spp.children.filter(ticket_tr=trID):


    #get_object_or_404 не используется т.к. 'RelatedManager' object has no attribute 'get_object_or_404'
    try:
        ticket_tr = ticket_spp.children.get(ticket_tr=trID)
    except TR.DoesNotExist:
        raise Http404("ТР не создавалось")

    try:
        ortr = ticket_tr.ortrtr_set.all()[0]
    except IndexError:
        raise Http404("Блока ОРТР нет")

    #request.session['ticket_tr_id'] = ticket_tr.id

    # if ticket_tr.ortrtr_set.all():

    #request.session['ortr_id'] = ortr.id

    #counter_str_ortr = ortr.ortr.count('\n')
    #if ortr.ots:
    #    counter_str_ots = ortr.ots.count('\n')
    #else:
        #counter_str_ots = 1


    return render(request, 'tickets/tr_view_save.html', {'ticket_tr': ticket_tr, 'ortr': ortr})


@cache_check
def tr_view(request, dID, tID, trID):
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


def for_tr_view(login, password, dID, tID, trID): #login, password
    spp_params = {}
    all_link = {}
    url = 'https://sss.corp.itmh.ru/dem_tr/dem_point.php?dID={}&tID={}&trID={}'.format(dID, tID, trID)
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 200:
        soup = BeautifulSoup(req.content.decode('utf-8'), "html.parser")
        search = soup.find_all('tr')

        for index, i in enumerate(search):
            if 'Перечень' in i.find_all('td')[0].text:
                total_services = []
                leng_services = i.find_all('td')[1].find_all('tr')
                for service_index in range(1, len(i.find_all('td')[1].find_all('tr'))-1):
                    services = i.find_all('td')[1].find_all('tr')[service_index].find_all('td')
                    var_list = []
                    for k in services:
                        var_list.append(k.text)
                    service = ' '.join(var_list)
                    total_services.append(service)

                spp_params['Перечень требуемых услуг'] = total_services
            elif 'Информация для' in i.find_all('td')[0].text:
                spp_params['Информация для разработки ТР'] = i.find_all('td')[1].text
            elif 'Узел подключения клиента' in i.find_all('td')[0].text:
                #print('!!!!!УЗел')

                node = re.search(r'\t(.+)\s+Статус', i.find_all('td')[1].text)

                #print(node.group(1))
                if 'Изменить' in i.find_all('td')[0].text:
                    spp_params['Узел подключения клиента'] = node.group(1)
                else:
                    #node = i.find_all('td')[0].find('a').get('href')
                    #match_node = re.search(r'(\d+), (\d+)', node)
                    #node_href = match_node.groups()
                    #spp_params['Узел подключения клиента'] = 'https://sss.corp.itmh.ru/building/address_begin.php?mode=selectAV&aID={}&parent={}'.format(*node_href)
                    spp_params['Узел подключения клиента'] = url
            elif 'Отключение' in i.find_all('td')[0].text and len(i.find_all('td')) > 1:
                try:
                    checked = i.find_all('td')[1].find('input')['checked']
                except KeyError:
                    spp_params[i.find_all('td')[0].text] = 'Нет'
                else:
                    spp_params[i.find_all('td')[0].text] = 'Требуется отключение'

            elif 'Тип / кат' in i.find_all('td')[0].text:
                file = {}
                files = i.find_all('td')[0].find_all('a')
                print('!!!Отклю')
                for item in range(len(files)):
                    if 'javascript' not in files[item].get('href'):
                        file[files[item].text] = files[item].get('href')
                        print(files[item].get('href'))
                        print(files[item].text)


                #elif 'Состав Заявки ТР' in i.find_all('td')[0].text:
                #for links in i.find_all('td')[1].find_all('a'):
                #    if 'trID' in links.get('href'):
                #        regex = 'tID=(\d+)&trID=(\d+)'
                #        match_href = re.search(regex, links.get('href'))
                #        total_link = [match_href.group(1), match_href.group(2)]
                #    else:
                #        total_link = None
                #    all_link[links.text] = total_link
                #spp_params['Состав Заявки ТР'] = all_link



            elif 'Время на реализацию, дней' in i.find_all('td')[0].text:
                spp_params['Решение ОТПМ'] = search[index+1].find('td').text
                #spp_params['Решение ОТПМ'] = spp_params['Решение ОТПМ'].replace('\r\n', '<br />').replace('\n', '<br />')
                spp_params['Решение ОТПМ'] = spp_params['Решение ОТПМ']
            '''elif 'Стоимость доп. Оборудования' in i.find_all('td')[0].text and i.find_all('td')[1].find('input'):
                if i.find_all('td')[1].find('input')['name'] == 'tr_OTO_Pay':
                    spp_params[i.find_all('td')[1].find('input')['name']] = i.find_all('td')[1].find('input')['value']
                if i.find_all('td')[1].find('input')['name'] == 'tr_OTS_Pay':
                    spp_params[i.find_all('td')[1].find('input')['name']] = i.find_all('td')[1].find('input')['value']
            elif 'Тип ТР' in i.find_all('td')[0].text:
                for option in i.find_all('td')[1].find('select').find_all('option'):
                    try:
                        selected_option = option['selected']
                    except KeyError:
                        selected_option = None
                    else:
                        spp_params['trOTMPType'] = option['value']
                spp_params.setdefault('trOTMPType', 0)
            elif 'Статья затрат' in i.find_all('td')[0].text:
                for option in i.find_all('td')[1].find('select').find_all('option'):
                    try:
                        selected_option = option['selected']
                    except KeyError:
                        selected_option = None
                    else:
                        spp_params['trArticle'] = option['value']
                spp_params.setdefault('trArticle', 0)'''
        if spp_params['Отключение'] == 'Требуется отключение':
            spp_params['Отключение'] = file
        search2 = soup.find_all('form')
        form_data = search2[1].find_all('input')
        for i in form_data:
            if i.attrs['type'] == 'hidden':
                if i['name'] == 'vID':
                    spp_params[i['name']] = i['value']
        return spp_params
    else:
        spp_params['Access denied'] = 'Access denied'
        return spp_params


def in_work_ortr(login, password):
    lines = []
    url = 'https://sss.corp.itmh.ru/dem_tr/demands.php?tech_uID=0&trStatus=inWorkORTR&curator=any&vName=&dSearch=&bID=1&searchType=param'
    req = requests.get(url, verify=False, auth=HTTPBasicAuth(login, password))
    if req.status_code == 200:
        soup = BeautifulSoup(req.content.decode('utf-8'), "html.parser")
        search_demand_num2 = soup.find_all('td', class_='demand_num2')
        search_demand_cust = soup.find_all('td', class_='demand_cust')
        search_demand_point = soup.find_all('td', class_='demand_point')
        search_demand_tech = soup.find_all('td', class_='demand_tech')
        search_demand_cur = soup.find_all('td', class_='demand_cur')
        #search_demand_stat = soup.find_all('td', class_='demand_stat')

        for index in range(len(search_demand_num2)-1):
            if search_demand_cur[index].text in ['Бражкин П.В.', 'Короткова И.В.', 'Полейко А.Л.', 'Гумеров Р.Т.']:
                pass
            else:

                lines.append([search_demand_num2[index].text, search_demand_num2[index].find('a').get('href')[(search_demand_num2[index].find('a').get('href').index('=')+1):], search_demand_cust[index].text, search_demand_point[index].text,
                          search_demand_tech[index].text, search_demand_cur[index].text]) #search_demand_stat[index].text
        for index in range(len(lines)):
            if 'ПТО' in lines[index][0]:
                lines[index][0] = lines[index][0][:lines[index][0].index('ПТО')]+' '+lines[index][0][lines[index][0].index('ПТО'):]
            for symbol_index in range(1, len(lines[index][3])):
                if lines[index][3][symbol_index].isupper() and lines[index][3][symbol_index-1].islower():
                    lines[index][3] = lines[index][3][:symbol_index]+' '+lines[index][3][symbol_index:]
                    break
    else:
        lines.append('Access denied')
    return lines

def client_new(list_switches, ppr, templates, counter_line_services, services_plus_desc, logic_csw, pps, sreda, port,
               device_client, device_pps, speed_port, model_csw, port_csw, logic_csw_1000, pointA, pointB, policer_cks,
               policer_vk, new_vk, exist_vk, policer_vm, new_vm, exist_vm, vm_inet, hotspot_points, hotspot_users, exist_client,
               camera_number, camera_model, voice, deep_archive, camera_place_one, camera_place_two, address, vgw, channel_vgw,
               ports_vgw, local_type, local_ports, sks_poe, sks_router, lvs_busy, lvs_switch, access_point, router_shpd,
               type_shpd, type_itv, cnt_itv, type_cks, type_portvk, type_portvm):


    result_services = []
    result_services_ots = None
    kad = 'Не требуется'

    if counter_line_services > 0:
        list_kad = []
        list_model_kad = []


        if len(list_switches) == 1:
            kad = list_switches[0][0]
            model_kad = list_switches[0][1]
        else:
            for i in range(len(list_switches)):
                if (list_switches[i][0].startswith('IAS')) or (list_switches[i][0].startswith('AR')):
                    pass
                else:
                    list_kad.append(list_switches[i][0])
                    list_model_kad.append(list_switches[i][1])
            kad = ' или '.join(list_kad)
            model_kad = ' или '.join(list_model_kad)

        if pps.endswith(', АВ'):
            pps = 'АВ ' + pps[:pps.index(', АВ')]
        elif pps.endswith(', КК'):
            pps = 'КК ' + pps[:pps.index(', КК')]
        elif pps.endswith(', УА'):
            pps = 'УПА ' + pps[:pps.index(', УА')]
        elif pps.endswith(', РУА'):
            pps = 'РУА ' + pps[:pps.index(', РУА')]
        else:
            print('Неверный узел связи')

        if counter_line_services == 1 and logic_csw == False:
            enviroment(result_services, sreda, ppr, templates, pps, kad, port, device_client, device_pps, speed_port, access_point)
        elif counter_line_services > 1:
            if logic_csw == False:
                for i in range(counter_line_services):
                    enviroment(result_services, sreda, ppr, templates, pps, kad, port, device_client, device_pps, speed_port, access_point)

        if logic_csw == True:
            static_vars = {}
            hidden_vars = {}
            static_vars['указать № порта'] = port_csw
            static_vars['указать модель коммутатора'] = model_csw
            static_vars['указать узел связи'] = pps
            static_vars['указать название коммутатора'] = kad
            static_vars['указать порт коммутатора'] = port
            if logic_csw_1000 == True:
                static_vars['100/1000'] = '1000'
            else:
                static_vars['100/1000'] = '100'
            if sreda == '1':
                print("Присоединение КК к СПД по медной линии связи." + '-' * 20)
                stroka = templates.get("Установка клиентского коммутатора")
                static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['медную линию связи/ВОЛС'] = 'медную линию связи'
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

            elif sreda == '2' or sreda == '4':
                if ppr:
                    print('-' * 20 + '\n' + "Присоединение КК к СПД по оптической линии ")
                    stroka = templates.get("Установка клиентского коммутатора")
                    static_vars['указать № ППР'] = ppr
                else:
                    print('-' * 20 + '\n' + "Установка клиентского коммутатора по оптической линии связи")
                    stroka = templates.get("Установка клиентского коммутатора")

                static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                static_vars['медную линию связи/ВОЛС'] = 'ВОЛС'
                hidden_vars['- Установить на стороне %указать узел связи% %указать конвертер/передатчик на стороне узла связи%'] = '- Установить на стороне %указать узел связи% %указать конвертер/передатчик на стороне узла связи%'
                hidden_vars['и %указать конвертер/передатчик на стороне клиента%'] = 'и %указать конвертер/передатчик на стороне клиента%'
                static_vars['указать конвертер/передатчик на стороне узла связи'] = device_pps
                static_vars['указать конвертер/передатчик на стороне клиента'] = device_client

                if logic_csw_1000 == True:
                    hidden_vars[
                        '-ВНИМАНИЕ! Совместно с ОНИТС СПД удаленно настроить клиентский коммутатор.'] = '-ВНИМАНИЕ! Совместно с ОНИТС СПД удаленно настроить клиентский коммутатор.'
                    hidden_vars[
                        '- Совместно с %ОИПМ/ОИПД% удаленно настроить клиентский коммутатор.'] = '- Совместно с %ОИПМ/ОИПД% удаленно настроить клиентский коммутатор.'
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

                #result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
                #return result_services


            elif sreda == '3':
                print("Присоединение к СПД по беспроводной среде передачи данных.")
                stroka = templates.get("Установка клиентского коммутатора")
                static_vars['медную линию связи/ВОЛС'] = 'медную линию связи'
                static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['указать модель беспроводных точек'] = access_point
                hidden_vars['- Создать заявку в Cordis на ОНИТС СПД для выделения реквизитов беспроводных точек доступа WDS/WDA.'] = '- Создать заявку в Cordis на ОНИТС СПД для выделения реквизитов беспроводных точек доступа WDS/WDA.'
                hidden_vars['- Установить на стороне %указать узел связи% и на стороне клиента беспроводные точки доступа %указать модель беспроводных точек% по решению ОАТТР.'] = '- Установить на стороне %указать узел связи% и на стороне клиента беспроводные точки доступа %указать модель беспроводных точек% по решению ОАТТР.'
                hidden_vars['- По заявке в Cordis выделить реквизиты для управления беспроводными точками.'] = '- По заявке в Cordis выделить реквизиты для управления беспроводными точками.'
                hidden_vars['- Совместно с ОИПД подключить к СПД и запустить беспроводные станции (WDS/WDA).'] = '- Совместно с ОИПД подключить к СПД и запустить беспроводные станции (WDS/WDA).'
                if access_point == 'Infinet H11':
                    hidden_vars[
                        '- Доставить в офис ОНИТС СПД беспроводные точки Infinet H11 для их настройки.'] = '- Доставить в офис ОНИТС СПД беспроводные точки Infinet H11 для их настройки.'
                    hidden_vars['После выполнения подготовительных работ в рамках заявки в Cordis на ОНИТС СПД и настройки точек в офисе ОНИТС СПД:'] = 'После выполнения подготовительных работ в рамках заявки в Cordis на ОНИТС СПД и настройки точек в офисе ОНИТС СПД:'
                else:
                    hidden_vars['После выполнения подготовительных работ в рамках заявки в Cordis на ОНИТС СПД:'] = 'После выполнения подготовительных работ в рамках заявки в Cordis на ОНИТС СПД:'
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))



    for service in services_plus_desc:
        if 'Интернет, DHCP' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            if logic_csw == True:
                result_services.append(enviroment_csw(sreda, templates))
            else:
                pass
            static_vars = {}
            hidden_vars = {}
            stroka = templates.get("Организация услуги ШПД в интернет access'ом.")
            static_vars['указать маску'] = '/32'
            result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

            if router_shpd == True:
                stroka = templates.get("Установка маршрутизатора")
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

        elif 'Интернет, блок Адресов Сети Интернет' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            if logic_csw == True:
                result_services.append(enviroment_csw(sreda, templates))
            else:
                pass
            static_vars = {}
            hidden_vars = {}
            if ('29' in service) or (' 8' in service):
                static_vars['указать маску'] = '/29'
            elif ('28' in service) or ('16' in service):
                static_vars['указать маску'] = '/28'
            else:
                static_vars['указать маску'] = '/30'
            if type_shpd == 'access':
                stroka = templates.get("Организация услуги ШПД в интернет access'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            elif type_shpd == 'trunk':
                stroka = templates.get("Организация услуги ШПД в интернет trunk'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

            if router_shpd == True:
                stroka = templates.get("Установка маршрутизатора")
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

        elif 'iTV' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            #if logic_csw == True:
            #    result_services.append(enviroment_csw(sreda, templates))
            #else:
            #    pass
            if logic_csw == True and type_itv == 'vl':
                for i in range(int(cnt_itv)):
                    result_services.append(enviroment_csw(sreda, templates))
            static_vars = {}
            hidden_vars = {}

            if type_itv == 'vl':
                if cnt_itv == 1:
                    static_vars['маска'] = '/30'
                elif 1 < cnt_itv < 6:
                    static_vars['маска'] = '/29'
                stroka = templates.get("Организация услуги Вебург.ТВ в отдельном vlan'е")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            elif type_itv == 'novl':
                for serv_inet in services_plus_desc:
                    if 'Интернет, блок Адресов Сети Интернет' in serv_inet:
                        stroka = templates.get("Организация услуги Вебург.ТВ в vlan'е новой услуги ШПД в интернет")
                        result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))


        elif 'ЦКС' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            if logic_csw == True:
                result_services.append(enviroment_csw(sreda, templates))

            static_vars = {}
            hidden_vars = {}

            static_vars['указать точку "A"'] = pointA
            static_vars['указать точку "B"'] = pointB
            static_vars['полисером Subinterface/портом подключения'] = policer_cks


            if '1000' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            elif '100' in service:
                static_vars['указать полосу'] = '100 Мбит/с'
            elif '10' in service:
                static_vars['указать полосу'] = '10 Мбит/с'
            elif '1' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            else:
                static_vars['указать полосу'] = 'Неизвестная полоса'

            if type_cks == 'access':
                stroka = templates.get("Организация услуги ЦКС Etherline access'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            elif type_cks == 'trunk':
                stroka = templates.get("Организация услуги ЦКС Etherline trunk'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))


        elif 'Порт ВЛС' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            if logic_csw == True:
                result_services.append(enviroment_csw(sreda, templates))
            else:
                pass
            static_vars = {}
            hidden_vars = {}
            if new_vk == True:
                stroka = templates.get("Организация услуги ВЛС")
                result_services.append(stroka)
                static_vars['указать ресурс ВЛС на договоре в Cordis'] = 'Для ВЛС, организованной по решению выше,'
            else:
                static_vars['указать ресурс ВЛС на договоре в Cordis'] = exist_vk
            if '1000' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            elif '100' in service:
                static_vars['указать полосу'] = '100 Мбит/с'
            elif '10' in service:
                static_vars['указать полосу'] = '10 Мбит/с'
            elif '1' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            else:
                static_vars['указать полосу'] = 'Неизвестная полоса'

            static_vars['полисером на Subinterface/на порту подключения'] = policer_vk
            if type_portvk == 'access':
                stroka = templates.get("Организация услуги порт ВЛС access'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            elif type_portvk == 'trunk':
                stroka = templates.get("Организация услуги порт ВСЛ trunk'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))


        elif 'Порт ВМ' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            if logic_csw == True:
                result_services.append(enviroment_csw(sreda, templates))
            else:
                pass
            static_vars = {}
            hidden_vars = {}
            if new_vm == True:
                stroka = templates.get("Организация услуги виртуальный маршрутизатор")
                result_services.append(stroka)
                static_vars['указать название ВМ'] = ', организованного по решению выше,'
            else:
                static_vars['указать название ВМ'] = exist_vm
            if '1000' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            elif '100' in service:
                static_vars['указать полосу'] = '100 Мбит/с'
            elif '10' in service:
                static_vars['указать полосу'] = '10 Мбит/с'
            elif '1' in service:
                static_vars['указать полосу'] = '1 Гбит/с'
            else:
                static_vars['указать полосу'] = 'Неизвестная полоса'

            static_vars['полисером на SVI/на порту подключения'] = policer_vm
            if vm_inet == True:
                static_vars['без доступа в интернет/с доступом в интернет'] = 'с доступом в интернет'
            else:
                static_vars['без доступа в интернет/с доступом в интернет'] = 'без доступа в интернет'
                hidden_vars['- Согласовать с клиентом адресацию для порта ВМ без доступа в интернет.'] = '- Согласовать с клиентом адресацию для порта ВМ без доступа в интернет.'

            if type_portvm == 'access':
                stroka = templates.get("Организация услуги порт виртуального маршрутизатора access'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            elif type_portvm == 'trunk':
                stroka = templates.get("Организация услуги порт виртуального маршрутизатора trunk'ом.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))


        elif 'HotSpot' in service:
            #hotspot_users = None
            static_vars = {}
            hidden_vars = {}
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)

            if ('премиум +' or 'премиум+') in service.lower():
                if logic_csw == True:
                    result_services.append(enviroment_csw(sreda, templates))
                static_vars['указать количество клиентов'] = hotspot_users
                static_vars["access'ом (native vlan) / trunk"] = "access'ом"
                if exist_client == True:
                    stroka = templates.get("Организация услуги Хот-спот Премиум + для существующего клиента.")
                else:
                    stroka = templates.get("Организация услуги Хот-спот Премиум + для нового клиента.")
                result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
            else:
                if logic_csw == True:
                    for i in range(int(hotspot_points)):
                        result_services.append(enviroment_csw(sreda, templates))
                    static_vars['указать название коммутатора'] = 'клиентского коммутатора'
                else:
                    static_vars['указать название коммутатора'] = kad
                if exist_client == True:
                    stroka = templates.get("Организация услуги Хот-спот %Стандарт/Премиум% для существующего клиента.")
                else:
                    stroka = templates.get("Организация услуги Хот-спот %Стандарт/Премиум% для нового клиента.")
                if 'премиум' in service.lower():
                    static_vars['Стандарт/Премиум'] = 'Премиум'
                    static_vars['указать модель станций'] = 'Ubiquiti UniFi'
                else:
                    static_vars['Стандарт/Премиум'] = 'Стандарт'
                    static_vars['указать модель станций'] = 'D-Link DIR-300'
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['указать количество станций'] = hotspot_points
                static_vars['ОАТТР/ОТИИ'] = 'ОАТТР'
                static_vars['указать количество клиентов'] = hotspot_users
                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                regex_counter = 'беспроводных станций: (\d+)'
                match_counter = re.search(regex_counter, stroka)
                counter_plur = int(match_counter.group(1))
                result_services.append(pluralizer_vars(stroka, counter_plur))


        elif 'Видеонаблюдение' in service:
            #cnt_camera = None
            print('-' * 20 + '\n' + '{}'.format(service.replace('|', ' ')))
            cameras = ['TRASSIR TR-D7111IR1W', 'TRASSIR TR-D7121IR1W', 'QTECH QVC-IPC-202VAE', 'QTECH QVC-IPC-202ASD', \
                       'TRASSIR TR-D3121IR1 v4', 'QTECH QVC-IPC-201E', 'TRASSIR TR-D2121IR3', 'QTECH QVC-IPC-502AS', \
                       'QTECH QVC-IPC-502VA', 'HiWatch DS-I453', 'QTECH QVC-IPC-501', 'TRASSIR TR-D2141IR3',
                       'HiWatch DS-I450']
            static_vars = {}
            hidden_vars = {}
            static_vars['указать модель камеры'] = camera_model
            if voice == True:
                static_vars['требуется запись звука / запись звука не требуется'] = 'требуется запись звука'
                hidden_vars[' и запись звука'] = ' и запись звука'
            else:
                static_vars['требуется запись звука / запись звука не требуется'] = 'запись звука не требуется'
            #regex_cnt_camera = ['(\d+)камер', '(\d+) камер', '(\d+) видеокамер', '(\d+)видеокамер']
            #for regex in regex_cnt_camera:
            #    match_cnt_camera = re.search(regex, service.lower())
            #    if match_cnt_camera:
            #        cnt_camera = match_cnt_camera.group(1)
            #        break


            if int(camera_number) < 3:
                stroka = templates.get("Организация услуги Видеонаблюдение с использованием PoE-инжектора")
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['указать количество линий'] = camera_number
                static_vars['указать количество камер'] = camera_number
                static_vars['указать количество инжекторов'] = camera_number
                static_vars['номер порта маршрутизатора'] = 'свободный'
                static_vars['0/3/7/15/30'] = deep_archive
                static_vars['указать адрес'] = address
                static_vars['указать место установки 1'] = camera_place_one

                if int(camera_number) == 2:
                    hidden_vars['-- %номер порта маршрутизатора%: %указать адрес%, Камера %указать место установки 2%, %указать модель камеры%, %требуется запись звука / запись звука не требуется%.'] = '-- %номер порта маршрутизатора%: %указать адрес%, Камера %указать место установки 2%, %указать модель камеры%, %требуется запись звука / запись звука не требуется%.'
                    hidden_vars['-- камеры %указать место установки 2% глубину хранения архива %0/3/7/15/30%[ и запись звука].'] = '-- камеры %указать место установки 2% глубину хранения архива %0/3/7/15/30%[ и запись звука].'
                    static_vars['указать место установки 2'] = camera_place_two
                static_vars[
                    'PoE-инжектор СКАТ PSE-PoE.220AC/15VA / OSNOVO Midspan-1/151A'] = 'PoE-инжектор СКАТ PSE-PoE.220AC/15VA'
                #result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                counter_plur = int(camera_number)
                result_services.append(pluralizer_vars(stroka, counter_plur))


            elif int(camera_number) == 5 or int(camera_number) == 9:
                stroka = templates.get("Организация услуги Видеонаблюдение с использованием POE-коммутатора и PoE-инжектора")
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['указать количество линий'] = str(int(camera_number)-1)
                static_vars['указать количество камер'] = camera_number
                if int(camera_number) == 5:
                    static_vars['POE-коммутатор D-Link DES-1005P / TP-Link TL-SF1005P'] = 'D-Link DES-1005P'
                    static_vars['указать номер порта POE-коммутатора'] = '5'
                    static_vars['номер камеры'] = '5'
                elif int(camera_number) == 9:
                    static_vars['POE-коммутатор D-Link DES-1005P / TP-Link TL-SF1005P'] = 'Atis PoE-1010-8P'
                    static_vars['указать номер порта POE-коммутатора'] = '10'
                    static_vars['номер камеры'] = '9'
                static_vars['номер порта маршрутизатора'] = 'свободный'
                static_vars['0/3/7/15/30'] = deep_archive
                static_vars['указать адрес'] = address
                list_cameras_one = []
                list_cameras_two = []
                for i in range(int(camera_number)-1):
                    extra_stroka_one = 'Порт {}: %указать адрес%, Камера №{}, %указать модель камеры%, %требуется запись звука / запись звука не требуется%\n'.format(i+1, i+1)
                    list_cameras_one.append(extra_stroka_one)
                for i in range(int(camera_number)):
                    extra_stroka_two = '-- камеры Камера №{} глубину хранения архива %0/3/7/15/30%< и запись звука>;\n'.format(i + 1)
                    list_cameras_two.append(extra_stroka_two)
                extra_extra_stroka_one = ''.join(list_cameras_one)
                extra_extra_stroka_two = ''.join(list_cameras_two)
                stroka = stroka[:stroka.index('- Организовать 1 линию от камеры')] + extra_extra_stroka_one + stroka[stroka.index('- Организовать 1 линию от камеры'):]
                stroka = stroka +'\n'+ extra_extra_stroka_two

                # result_services.append(analyzer_vars(stroka, static_vars))


                static_vars[
                    'PoE-инжектор СКАТ PSE-PoE.220AC/15VA / OSNOVO Midspan-1/151A'] = 'PoE-инжектор СКАТ PSE-PoE.220AC/15VA'
                static_vars['указать количество POE-коммутаторов'] = '1'

                # result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                counter_plur = int(camera_number)-1
                result_services.append(pluralizer_vars(stroka, counter_plur))
            else:
                stroka = templates.get("Организация услуги Видеонаблюдение с использованием POE-коммутатора")
                if sreda == '2' or sreda == '4':
                    static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
                else:
                    static_vars['ОИПМ/ОИПД'] = 'ОИПД'
                static_vars['указать количество линий'] = camera_number
                static_vars['указать количество камер'] = camera_number
                if 5 < int(camera_number) < 9:
                    static_vars['POE-коммутатор D-Link DES-1005P / TP-Link TL-SF1005P'] = 'Atis PoE-1010-8P'
                    static_vars['указать номер порта POE-коммутатора'] = '10'
                elif 2 < int(camera_number) < 5:
                    static_vars['POE-коммутатор D-Link DES-1005P / TP-Link TL-SF1005P'] = 'D-Link DES-1005P'
                    static_vars['указать номер порта POE-коммутатора'] = '5'
                static_vars['номер порта маршрутизатора'] = 'свободный'
                static_vars['0/3/7/15/30'] = deep_archive
                static_vars['указать адрес'] = address

                list_cameras_one = []
                list_cameras_two = []
                for i in range(int(camera_number)):
                    extra_stroka_one = 'Порт {}: %указать адрес%, Камера №{}, %указать модель камеры%, %требуется запись звука / запись звука не требуется%;\n'.format(
                        i + 1, i + 1)
                    list_cameras_one.append(extra_stroka_one)
                for i in range(int(camera_number)):
                    extra_stroka_two = '-- камеры Камера №{} глубину хранения архива %0/3/7/15/30%< и запись звука>;\n'.format(
                        i + 1)
                    list_cameras_two.append(extra_stroka_two)
                extra_extra_stroka_one = ''.join(list_cameras_one)
                extra_extra_stroka_two = ''.join(list_cameras_two)
                print('!!!!!!!!!!!!!!!!!')
                print(stroka)
                stroka = stroka[:stroka.index('порты POE-коммутатора:')] + 'порты POE-коммутатора:\n' + extra_extra_stroka_one + '\n \nОВИТС проведение работ:\n' + stroka[stroka.index('- Произвести настройку'):]
                stroka = stroka + '\n' + extra_extra_stroka_two
                static_vars['указать количество POE-коммутаторов'] = '1'

                #result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))

                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                counter_plur = int(camera_number)
                result_services.append(pluralizer_vars(stroka, counter_plur))

        elif 'Телефон' in service:
            hidden_vars = {}
            result_services_ots = []
            static_vars = {}

            if service.endswith('|'):
                if logic_csw == True:
                    result_services.append(enviroment_csw(sreda, templates))
                    static_vars[
                        'клиентского коммутатора / КАД (указать маркировку коммутатора)'] = 'клиентского коммутатора'
                elif logic_csw == False:
                    static_vars['клиентского коммутатора / КАД (указать маркировку коммутатора)'] = kad
                stroka = templates.get("Установка тел. шлюза у клиента")
                static_vars['указать модель тел. шлюза'] = vgw
                if vgw in ['Eltex TAU-2M.IP', 'Eltex RG-1404G или Eltex TAU-4M.IP', 'Eltex TAU-8.IP']:
                    static_vars['WAN порт/Ethernet Порт 0'] = 'WAN порт'
                else:
                    static_vars['WAN порт/Ethernet Порт 0'] = 'Ethernet Порт 0'
                    static_vars['указать модель тел. шлюза'] = vgw + ' c кабелем для коммутации в плинт'
                result_services_ots.append(analyzer_vars(stroka, static_vars, hidden_vars))
                if 'ватс' in service.lower():
                    stroka = templates.get("ВАТС (Подключение по аналоговой линии)")
                    static_vars['идентификатор тел. шлюза'] = 'установленный по решению выше'
                    static_vars['указать модель тел. шлюза'] = vgw
                    static_vars['указать количество портов'] = ports_vgw
                    if 'базов' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'базовым набором сервисов'
                    elif 'расшир' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'расширенным набором сервисов'

                    static_vars['указать количество телефонных линий'] = ports_vgw
                    if ports_vgw == 1:
                        static_vars['указать порты тел. шлюза'] = '1'
                    else:
                        static_vars['указать порты тел. шлюза'] = '1-{}'.format(ports_vgw)
                    static_vars['указать количество каналов'] = channel_vgw
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))
                else:
                    stroka = templates.get(
                        "Подключение аналогового телефона с использованием тел.шлюза на стороне клиента")
                    static_vars['указать модель тел. шлюза'] = vgw


                    static_vars['указать количество телефонных линий'] = channel_vgw
                    static_vars['указать количество каналов'] = channel_vgw
                    if ports_vgw == 1:
                        static_vars['указать порты тел. шлюза'] = '1'
                    else:
                        static_vars['указать порты тел. шлюза'] = '1-{}'.format(channel_vgw)
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))
            elif service.endswith('/'):
                stroka = templates.get("Установка тел. шлюза на ППС")

                static_vars['указать модель тел. шлюза'] = vgw
                static_vars['указать узел связи'] = pps
                result_services_ots.append(analyzer_vars(stroka, static_vars, hidden_vars))
                if 'ватс' in service.lower():
                    stroka = templates.get("ВАТС (Подключение по аналоговой линии)")
                    if 'базов' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'базовым набором сервисов'
                    elif 'расшир' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'расширенным набором сервисов'
                    static_vars['идентификатор тел. шлюза'] = 'установленный по решению выше'

                    static_vars['указать количество телефонных линий'] = ports_vgw
                    static_vars['указать количество портов'] = ports_vgw
                    if ports_vgw == 1:
                        static_vars['указать порты тел. шлюза'] = '1'
                    else:
                        static_vars['указать порты тел. шлюза'] = '1-{}'.format(ports_vgw)

                    static_vars['указать количество каналов'] = channel_vgw
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))
                else:
                    stroka = templates.get("Подключение аналогового телефона с использованием голосового шлюза на ППС")
                    static_vars['идентификатор тел. шлюза'] = 'установленного по решению выше'

                    static_vars['указать количество телефонных линий'] = channel_vgw
                    static_vars['указать количество каналов'] = channel_vgw
                    if ports_vgw == 1:
                        static_vars['указать порты тел. шлюза'] = '1'
                    else:
                        static_vars['указать порты тел. шлюза'] = '1-{}'.format(channel_vgw)
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))

            elif service.endswith('\\'):
                if 'ватс' in service.lower():
                    stroka = templates.get("ВАТС (Подключение по аналоговой линии)")
                    if 'базов' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'базовым набором сервисов'
                    elif 'расшир' in service.lower():
                        static_vars[
                            'базовым набором сервисов / расширенным набором сервисов'] = 'расширенным набором сервисов'

                    static_vars['указать количество телефонных линий'] = ports_vgw
                    static_vars['указать количество портов'] = ports_vgw
                    if ports_vgw == 1:
                        static_vars['указать порты тел. шлюза'] = '1'
                    else:
                        static_vars['указать порты тел. шлюза'] = '1-{}'.format(ports_vgw)
                    static_vars['указать количество каналов'] = channel_vgw
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))
                else:
                    stroka = templates.get("Подключение аналогового телефона с использованием голосового шлюза на ППС")
                    static_vars['указать узел связи'] = pps

                    static_vars['указать количество телефонных линий'] = channel_vgw
                    static_vars['указать количество каналов'] = channel_vgw
                    stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                    regex_counter = 'Организовать (\d+)'
                    match_counter = re.search(regex_counter, stroka)
                    counter_plur = int(match_counter.group(1))
                    result_services_ots.append(pluralizer_vars(stroka, counter_plur))
            else:
                if 'ватс' in service.lower():

                    static_vars['указать количество каналов'] = channel_vgw
                    if 'базов' in service.lower():
                        stroka = templates.get("ВАТС Базовая(SIP регистрация через Интернет)")

                    elif 'расшир' in service.lower():
                        stroka = templates.get("ВАТС Расширенная(SIP регистрация через Интернет)")
                        static_vars['указать количество портов'] = ports_vgw
                    result_services_ots.append(analyzer_vars(stroka, static_vars, hidden_vars))
                else:
                    stroka = templates.get(
                        "Подключения по цифровой линии с использованием протокола SIP, тип линии «SIP регистрация через Интернет»")

                    static_vars['указать количество каналов'] = channel_vgw
                    result_services_ots.append(analyzer_vars(stroka, static_vars, hidden_vars))

        elif 'ЛВС' in service:
            print('{}'.format(service.replace('|', ' ')) + '-' * 20)
            static_vars = {}
            hidden_vars = {}

            static_vars['2-23'] = local_ports
            if local_type == 'СКС':
                stroka = templates.get("Организация СКС на %2-23% {порт}")
                if sks_poe == True:
                    hidden_vars['ОИПД подготовиться к работам:\n- Получить на складе территории PoE-инжектор %указать модель PoE-инжектора% - %указать количество% шт.'] = 'ОИПД подготовиться к работам:\n- Получить на складе территории PoE-инжектор %указать модель PoE-инжектора% - %указать количество% шт.'
                if sks_router == True:
                    hidden_vars['- Подключить %2-23% {организованную} {линию} связи в ^свободный^ ^порт^ маршрутизатора клиента.'] = '- Подключить %2-23% {организованную} {линию} связи в ^свободный^ ^порт^ маршрутизатора клиента.'
                static_vars['указать количество'] = local_ports
                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                counter_plur = int(local_ports)
                result_services.append(pluralizer_vars(stroka, counter_plur))
            else:
                stroka = templates.get("Организация ЛВС на %2-23% {порт}")
                if lvs_busy == True:
                    hidden_vars['МКО:\n- В связи с тем, что у клиента все порты на маршрутизаторе заняты необходимо с клиентом согласовать перерыв связи по одному из подключенных устройств к маршрутизатору.\nВо время проведения работ данная линия будет переключена из маршрутизатора клиента в проектируемый коммутатор.'] = 'МКО:\n- В связи с тем, что у клиента все порты на маршрутизаторе заняты необходимо с клиентом согласовать перерыв связи по одному из подключенных устройств к маршрутизатору.\nВо время проведения работ данная линия будет переключена из маршрутизатора клиента в проектируемый коммутатор.\n'
                    hidden_vars['- По согласованию с клиентом высвободить LAN-порт на маршрутизаторе клиента переключив сущ. линию для ЛВС клиента из маршрутизатора клиента в свободный порт установленного коммутатора.'] = '- По согласованию с клиентом высвободить LAN-порт на маршрутизаторе клиента переключив сущ. линию для ЛВС клиента из маршрутизатора клиента в свободный порт установленного коммутатора.'
                    hidden_vars['- Подтвердить восстановление связи для порта ЛВС который был переключен в установленный коммутатор.'] = '- Подтвердить восстановление связи для порта ЛВС который был переключен в установленный коммутатор.'
                static_vars['указать модель коммутатора'] = lvs_switch
                if lvs_switch == ('TP-Link TL-SG105 V4' or 'ZYXEL GS1200-5'):
                    static_vars['5/8/16/24'] = '5'
                elif lvs_switch == ('TP-Link TL-SG108 V4' or 'ZYXEL GS1200-8'):
                    static_vars['5/8/16/24'] = '8'
                elif lvs_switch == 'D-link DGS-1100-16/B':
                    static_vars['5/8/16/24'] = '16'
                elif lvs_switch == 'D-link DGS-1100-24/B':
                    static_vars['5/8/16/24'] = '24'
                stroka = analyzer_vars(stroka, static_vars, hidden_vars)
                print('chech lvs stroka')
                print(stroka)
                counter_plur = int(local_ports)
                result_services.append(pluralizer_vars(stroka, counter_plur))


    index_template = 1
    titles = []
    for i in range(len(result_services)):
        result_services[i] = '{}. '.format(index_template) + result_services[i]
        titles.append(result_services[i][:result_services[i].index('---')])
        index_template += 1

    if result_services_ots == None:
        pass
    else:
        for i in range(len(result_services_ots)):
            result_services_ots[i] = '{}. '.format(index_template) + result_services_ots[i]
            titles.append(result_services_ots[i][:result_services_ots[i].index('---')])
            index_template += 1


    #titles = ''.join(titles)
    #result_services = ''.join(result_services)
    print(titles)
    print(result_services)

    return titles, result_services, result_services_ots, kad


def analyzer_vars(stroka, static_vars, hidden_vars):
    '''Данная функция принимает строковую переменную, содержащую шаблон услуги со страницы
    Типовые блоки технического решения. Ищет в шаблоне блоки <> и сравнивает с аналогичными переменными из СПП.
    По средством доп. словаря формирует итоговый словарь содержащий блоки из СПП, которые
    есть в блоках шаблона(чтобы не выводить неактуальный блок) и блоки шаблона, которых не было в блоках
    из СПП(чтобы не пропустить неучтенный блок)
    Передаем переменные, т.к. переменные из глобал видятся, а из другой функции нет.
'''
    #    блок для определения необходимости частных строк <>
    list_var_lines = []
    list_var_lines_in = []
    regex_var_lines = '<(.+?)>'
    match_var_lines = re.finditer(regex_var_lines, stroka, flags=re.DOTALL)

    for i in match_var_lines:
        print('совпадения <>')
        print(i)
        list_var_lines.append(i.group(1))

    for i in list_var_lines:
        print(i)
        if hidden_vars.get(i):
            stroka = stroka.replace('<{}>'.format(i), hidden_vars[i])

        else:
            stroka = stroka.replace('<{}>'.format(i), '  ')

    regex_var_lines_in = '\[(.+?)\]'
    match_var_lines_in = re.finditer(regex_var_lines_in, stroka, flags=re.DOTALL)
    print(match_var_lines_in)
    for i in match_var_lines_in:
        print('совпадения []')
        print(i)
        list_var_lines_in.append(i.group(1))

    for i in list_var_lines_in:
        print(i)
        if hidden_vars.get(i):
            stroka = stroka.replace('[{}]'.format(i), i)
        else:
            stroka = stroka.replace('[{}]'.format(i), '  ')


    if len(list_var_lines) > 0:
        stroka = stroka.split('  \n')
        stroka = ''.join(stroka)
        stroka = stroka.replace('    ', ' ')
        if '\n\n\n' in stroka:
            stroka = stroka.replace('\n\n\n', '\n')
        elif '\n \n \n \n' in stroka:
            stroka = stroka.replace('\n \n \n \n', '\n')

    # блок для заполнения %%
    ckb_vars = {}
    dynamic_vars = {}
    regex = '%([\s\S]+?)%'
    match = re.finditer(regex, stroka, flags=re.DOTALL)  #
    for i in match:
        ckb_vars[i.group(1)] = '%'+i.group(1)+'%'

    for key in static_vars.keys():
        if key in ckb_vars:
            del ckb_vars[key]
            dynamic_vars[key] = static_vars[key]

    dynamic_vars.update(ckb_vars)
    for key in dynamic_vars.keys():
        print(dynamic_vars[key])
    for key in dynamic_vars.keys():
        print(key)
        stroka = stroka.replace('%{}%'.format(key), dynamic_vars[key])
    #for key in dynamic_vars.keys():
    #    if dynamic_vars[key] == None:
    #        stroka = stroka.replace('%{}%'.format(key), input('Указать свое значение "{}": '.format(key)))
    #    else:
    #        logic = sss.state('"{}": {}'.format(key, dynamic_vars[key]))
    #        if logic == 'y':
    #            stroka = stroka.replace('%{}%'.format(key), dynamic_vars[key])
            #elif logic == 'n':
            #    stroka = stroka.replace('%{}%'.format(key), input('Указать свое значение: '))
    return stroka

def pluralizer_vars(stroka, counter_plur):
    '''Данная функция на основе количества устройств в шаблоне меняет ед./множ. число связанных слов'''
    morph = pymorphy2.MorphAnalyzer()
    regex = '{(\w+?)}'
    match = re.finditer(regex, stroka, flags=re.DOTALL)  #
    for i in match:
        replased_word = '{' + i.group(1) + '}'
        pluralize = morph.parse(i.group(1))[0]
        stroka = stroka.replace(replased_word, pluralize.make_agree_with_number(counter_plur).word)
    regex_plur = '\^(\w+?)\^'
    match_plur = re.finditer(regex_plur, stroka, flags=re.DOTALL)
    if counter_plur == 1:
        for i in match_plur:
            replased_word = '^' + i.group(1) + '^'
            pluralize = morph.parse(i.group(1))[0]
            stroka = stroka.replace(replased_word, pluralize.inflect({'sing'}).word)
    elif counter_plur > 1:
        for i in match_plur:
            replased_word = '^' + i.group(1) + '^'
            pluralize = morph.parse(i.group(1))[0]
            if 'ADJF' in pluralize.tag:
                stroka = stroka.replace(replased_word, pluralize.inflect({'nomn', 'plur'}).word)
            elif 'NOUN' in pluralize.tag:
                stroka = stroka.replace(replased_word, pluralize.inflect({'plur'}).word)
    return stroka



def enviroment(result_services, sreda, ppr, templates, pps, kad, port, device_client, device_pps, speed_port, access_point):
    if sreda == '1':
        print("Присоединение к СПД по медной линии связи."+'-'*20)
        static_vars = {}
        hidden_vars = {}
        stroka = templates.get("Присоединение к СПД по медной линии связи.")
        static_vars['указать узел связи'] = pps
        static_vars['указать название коммутатора'] = kad
        static_vars['указать порт коммутатора'] = port
        static_vars['ОИПМ/ОИПД'] = 'ОИПД'
        result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
        return result_services

    if sreda == '2' or sreda == '4':
        static_vars = {}
        if ppr:
            print('-' * 20 + '\n' + "Присоединение к СПД по оптической линии связи с простоем связи услуг.")
            stroka = templates.get("Присоединение к СПД по оптической линии связи с простоем связи услуг.")
            static_vars['указать № ППР'] = ppr
        else:
            print('-' * 20 + '\n' + "Присоединение к СПД по оптической линии связи.")
            stroka = templates.get("Присоединение к СПД по оптической линии связи.")
        print("Присоединение к СПД по оптической линии связи."+'-'*20)

        hidden_vars = {}
        static_vars['указать узел связи'] = pps
        static_vars['указать название коммутатора'] = kad
        static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
        static_vars['указать порт коммутатора'] = port
        static_vars['указать режим работы порта'] = speed_port
        static_vars['указать конвертер/передатчик на стороне узла связи'] = device_pps
        static_vars['указать конвертер/передатчик на стороне клиента'] = device_client

        result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
        return result_services


    elif sreda == '3':
        print("Присоединение к СПД по беспроводной среде передачи данных.")
        static_vars = {}
        hidden_vars = {}
        stroka = templates.get("Присоединение к СПД по беспроводной среде передачи данных.")
        static_vars['указать узел связи'] = pps
        static_vars['указать название коммутатора'] = kad

        static_vars['указать порт коммутатора'] = port
        static_vars['указать модель беспроводных точек'] = access_point
        if access_point == 'Infinet H11':
            hidden_vars['- Доставить в офис ОНИТС СПД беспроводные точки Infinet H11 для их настройки.'] = '- Доставить в офис ОНИТС СПД беспроводные точки Infinet H11 для их настройки.'
            hidden_vars[' и настройки точек в офисе ОНИТС СПД'] = ' и настройки точек в офисе ОНИТС СПД'

        result_services.append(analyzer_vars(stroka, static_vars, hidden_vars))
        return result_services



def enviroment_csw(sreda, templates):
    '''Добавляет блок организации медной линии от КК'''
    static_vars = {}
    hidden_vars = {}
    stroka = templates.get("Присоединение к СПД по медной линии связи.")
    static_vars['указать узел связи'] = 'клиентского коммутатора'
    static_vars['указать название коммутатора'] = 'установленный по решению выше'
    static_vars['указать порт коммутатора'] = 'свободный'
    if sreda == '2' or sreda == '4':
        static_vars['ОИПМ/ОИПД'] = 'ОИПМ'
    else:
        static_vars['ОИПМ/ОИПД'] = 'ОИПД'
    return analyzer_vars(stroka, static_vars, hidden_vars)











#def datatr(request):
#    if request.method == 'POST':
#        linkform = LinkForm(request.POST)
#        success = False
#        if linkform.is_valid():
#            print(linkform.cleaned_data)
#            #kad_model = portform.cleaned_data
#            spplink = linkform.cleaned_data['spplink']

#            success = True

#            services_plus_desc, counter_line_services, pps, turnoff, sreda, tochka, points_hotspot, oattr, address = parse_tr(username, password, spplink)
#            print(services_plus_desc)
#            request.session['services_plus_desc'] = services_plus_desc
#            request.session['counter_line_services'] = counter_line_services

#            for i in services_plus_desc:
#                if 'HotSpot' in i:
#                    if points_hotspot == None:
#                        return redirect('hotspot')


#            context = {'services_plus_desc': services_plus_desc, 'pps': pps, 'turnoff': turnoff, 'oattr': oattr, 'success': success, 'linkform': linkform}
#            return render(request, 'tickets/datatr.html', context)
#    else:
#        linkform = LinkForm()
#    return render(request, 'tickets/datatr.html', {'linkform': linkform})

from django.http import JsonResponse

def tr_spin(request):
    text = 'This is my statement one.&#13;&#10;This is my statement2'
    return render(request, 'tickets/spinner.html', {'text': text})

def spp_json(request):
    data = list(SPP.objects.values())
    return JsonResponse(data, safe=False)


from django.forms import formset_factory
#ArticleFormSet = formset_factory(ListResourcesForm, extra=2)
#formset = ArticleFormSet()

def test_formset(request):
    ono = request.session['ono']
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
                    return redirect('test_formset')
                else:
                    for i in unselected_ono:
                        if selected_ono[0][-2] == i[-2]: #to do сейчас проверка по КАД. По точке подключения нужна? Хорошо посмотреть 00128733
                            selected_ono.append(i)
                    request.session['selected_ono'] = selected_ono
                    return redirect('show_resources')
            else:
                messages.warning(request, 'Ресурсы не выбраны')
                return redirect('test_formset')

    else:
        formset = ListResourcesFormSet()
        ono_for_formset = []
        for resource_for_formset in ono:
            resource_for_formset.pop(5)
            resource_for_formset.pop(1)
            resource_for_formset.pop(0)
            ono_for_formset.append(resource_for_formset)

        context = {
            'ono_for_formset': ono_for_formset,
            #'contract': contract,
            'formset': formset
        }

        return render(request, 'tickets/test_formset.html', context)