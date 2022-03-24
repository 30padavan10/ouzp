from django.test import TestCase
from django.test import SimpleTestCase

# Create your tests here.
from django.contrib.auth.models import User

from django.test import Client
from .models import SPP, TR, OrtrTR
from .forms import HotspotForm
from .views import hotspot

import os
from pathlib import Path
from dotenv import load_dotenv
BASE_DIR = Path(__file__).resolve().parent.parent


dotenv_path = os.path.join(BASE_DIR, '.env')
load_dotenv(dotenv_path)
TEST_USER = os.getenv('TEST_USER')
TEST_PASS = os.getenv('TEST_PASS')

from django.urls import reverse, resolve
import json
from django.core.cache import cache


class SPPModelTests(TestCase):
    dID = "142748"
    ticket_tr = '72964'
    def setUp(self):
        self.user = User.objects.create_user(TEST_USER, 'test@test.com', TEST_PASS, last_name='TEST')
        # Для создания объекта пользователя используется метод именно create_user, а не create, т.к. при создании
        # через create пароль будет храниться в открытом виде и такой объект нельзя использовать для
        # аутентификации

        spp = SPP.objects.create(id=1, dID=self.dID, ticket_k="2022_01732", client='ООО "Оптимус Групп" / 00337785',
                            type_ticket="Коммерческая", manager="Потапова А. А.",
                           technolog="Русских К.С.", task_otpm="Спроектировать ТР по переезду, адрес: г. Березовский, ул. Кирова, д.63, офис 210 (2этаж)",
                           services='["\nИнтернет, DHCP\nг.Березовский, ул.Кирова, д.63, оф.210\nПеренос ШПД 10 Мбит/с\n \n"]',
                           des_tr='[{"г.Березовский, ул.Кирова, д.63, оф.210": null}, {"Техрешение №72964": ["214392", "72964"]}]',
                           comment="roar", version="1",
                           user=self.user)

        tr = TR.objects.create(
            ticket_k=spp,
            ticket_tr='72964',
            pps='БЗК Кирова 63 П1 (подъезд 4 эт), АВ',
            turnoff=False,
            oattr = '''ТР написано без выезда технолога.''',
            services=["Интернет, DHCP Перенос ШПД 10 Мбит/с"],
            connection_point='Кирова, д.63, оф.210',
            kad='SW008-AR15-08.ekb',
            vID='3136'
        )

        ortrtr = OrtrTR.objects.create(
            ticket_tr=tr,
            ortr="""Клиент: 00337785 ООО "Оптимус Групп"
                Точка подключения: Березовский, Восточная, д. 3/а, офис 605
                Логическое подключение:
                - ППС БЗК Восточная 3/а Э-1 (подвал офисного здания)
                - коммутатор SW460-AR15-08.ekb
                - порт Ethernet1/16"""
        )


    def test_spp_view_save(self):
        """
        test open html page saved ticket spp
        """
        spp_db = SPP.objects.get(dID=self.dID)

        #response = self.client.get('/db/142748-1/')
        response = self.client.get(reverse('spp_view_save', args=(self.dID, spp_db.id)))
        # args - если используются позиционные параметры, kwargs - если используются ключевые параметры

        spp_response = response.context['current_ticket_spp']

        self.assertEqual(spp_response.dID, spp_db.dID)
        self.assertEqual(spp_response.ticket_k, spp_db.ticket_k)
        #self.assertEqual(response.status_code, 200)

    def test_tr_view_save(self):
        """
        test open html page saved ticket tr
        """
        ticket_spp_db = SPP.objects.get(dID=self.dID)

        response = self.client.get(reverse('tr_view_save', args=(self.dID, ticket_spp_db.id, self.ticket_tr)))
        # args - если используются позиционные параметры, kwargs - если используются ключевые параметры

        with open('tr222tr.txt', 'w') as f_o:    # только для проверки того что вообще появляется в контексте
            f_o.write(str(response.context))

        self.assertEqual(response.status_code, 200)


    def test_private_page(self):
        """
        test open html page private_page
        """
        self.client.login(username=TEST_USER, password=TEST_PASS)
        response = self.client.get('')

        with open('tr222tr.txt', 'w') as f_o:    # только для проверки того что вообще появляется в контексте
            f_o.write(str(response.context))


        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'tickets/private_page.html')

    def test_forms(self):
        """
        test valid form
        """
        form_data = {'hotspot_points': '1', 'hotspot_users': '10'}
        form = HotspotForm(data=form_data)
        self.assertTrue(form.is_valid())

    # def test_forms(self):
    #     response = self.client.post(reverse('hotspot'), {'hotspot_points': '1', 'hotspot_users': '10'})
    #     self.assertFormError(response, 'HotspotForm', 'hotspot_points', 'This field is required.')

    def test_data(self):
        """
        test open html page data
        """
        with open('data.json', encoding='utf-8') as json_file:
            value_vars = json.load(json_file)

        session = self.client.session
        for k, v in value_vars.items():
            if k.startswith('_'):
                pass
            else:
                session.update({k: v})

        session.save()
        self.client.login(username=TEST_USER, password=TEST_PASS)
        credent = dict()
        credent.update({'username': TEST_USER})
        credent.update({'password': TEST_PASS})
        cache.set(self.user, credent, timeout=3600)
        response = self.client.get(reverse('data')) #, follow=True
        self.assertEqual(response.status_code, 302)



class TestUrls(SimpleTestCase):
    """Данный вид теста показывает только то, что url имени соответствует нужное представление"""
    def test_url_is_resolved(self):
        url = reverse('hotspot')
        print(resolve(url))
        print('test_url')
        self.assertEqual(resolve(url).func, hotspot)






