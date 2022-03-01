from django.test import TestCase

# Create your tests here.

from django.test import Client
from .models import SPP, User



from django.urls import reverse

class SPPModelTests(TestCase):

    def setUp(self):
        u = User.objects.create(username='john')

        SPP.objects.create(dID="142748", ticket_k="2022_01732", client='ООО "Оптимус Групп" / 00337785',
                            type_ticket="Коммерческая", manager="Потапова А. А.",
                           technolog="Русских К.С.", task_otpm="Спроектировать ТР по переезду, адрес: г. Березовский, ул. Кирова, д.63, офис 210 (2этаж)",
                           services='["\nИнтернет, DHCP\nг.Березовский, ул.Кирова, д.63, оф.210\nПеренос ШПД 10 Мбит/с\n \n"]',
                           des_tr='[{"г.Березовский, ул.Кирова, д.63, оф.210": null}, {"Техрешение №72964": ["214392", "72964"]}]',
                           comment="roar", version="1", created="",
                           complited="", user=u)

    def test_get_ticket(self):
        """
        was_published_recently() returns False for questions whose pub_date
        is in the future.
        """
        #pp = SPP.objects.filter(ticket_k='2022_01732')

        response = self.client.get('/db/142748-1/', {'username': 'pankov', 'password': 'WoW234Nerulit'})
        self.assertEqual(response.status_code, 200)