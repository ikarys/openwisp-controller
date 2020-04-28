from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_netjsonconfig import settings as app_settings
from django_netjsonconfig.base.config import AbstractConfig, TemplatesThrough
from django_netjsonconfig.base.config import TemplatesVpnMixin as BaseMixin
from django_netjsonconfig.base.device import AbstractDevice
from django_netjsonconfig.base.tag import AbstractTaggedTemplate, AbstractTemplateTag
from django_netjsonconfig.base.template import AbstractTemplate
from django_netjsonconfig.base.vpn import AbstractVpn, AbstractVpnClient
from django_netjsonconfig.validators import mac_address_validator
from sortedm2m.fields import SortedManyToManyField
from taggit.managers import TaggableManager

from openwisp_users.mixins import OrgMixin, ShareableOrgMixin
from openwisp_utils.base import KeyField, UUIDModel

from .utils import get_default_templates_queryset


class TemplatesVpnMixin(BaseMixin):
    class Meta:
        abstract = True

    def get_default_templates(self):
        """ see ``openwisp_controller.config.utils.get_default_templates_queryset`` """
        queryset = super().get_default_templates()
        assert self.device
        return get_default_templates_queryset(self.device.organization_id,
                                              queryset=queryset)

    @classmethod
    def clean_templates_org(cls, action, instance, pk_set, **kwargs):
        templates = cls.get_templates_from_pk_set(action, pk_set)
        if not templates:
            return templates
        # when using the admin, templates will be a list
        # we need to get the queryset from this list in order to proceed
        if not isinstance(templates, models.QuerySet):
            template_model = cls.templates.rel.model
            pk_list = [template.pk for template in templates]
            templates = template_model.objects.filter(pk__in=pk_list)
        # lookg for invalid templates
        invalids = templates.exclude(organization=instance.device.organization) \
                            .exclude(organization=None) \
                            .values('name')

        if templates and invalids:
            names = ''
            for invalid in invalids:
                names = '{0}, {1}'.format(names, invalid['name'])
            names = names[2:]
            message = _('The following templates are owned by organizations '
                        'which do not match the organization of this '
                        'configuration: {0}').format(names)
            raise ValidationError(message)
        # return valid templates in order to save computation
        # in the following operations
        return templates

    @classmethod
    def clean_templates(cls, action, instance, pk_set, **kwargs):
        """
        adds organization validation
        """
        templates = cls.clean_templates_org(action, instance, pk_set, **kwargs)
        # perform validation of configuration (local config + templates)
        super().clean_templates(action, instance, templates, **kwargs)


# if unique attribute for NETJSONCONFIG_HARDWARE_ID_OPTIONS is not explicitely mentioned,
# consider it to be False
if not getattr(settings, 'NETJSONCONFIG_HARDWARE_ID_OPTIONS', {}).get('unique'):
    app_settings.HARDWARE_ID_OPTIONS.update({'unique': False})


class Device(OrgMixin, AbstractDevice):
    """
    Concrete Device model
    """
    name = models.CharField(max_length=64, unique=False, db_index=True)
    mac_address = models.CharField(
        max_length=17,
        db_index=True,
        unique=False,
        validators=[mac_address_validator],
        help_text=_('primary mac address')
    )

    class Meta(AbstractDevice.Meta):
        unique_together = (
            ('name', 'organization'),
            ('mac_address', 'organization'),
            ('hardware_id', 'organization'),
        )
        abstract = False

    def get_temp_config_instance(self, **options):
        c = super().get_temp_config_instance(**options)
        c.device = self
        return c

    def save(self, *args, **kwargs):
        if not self.key:
            try:
                shared_secret = self.organization.config_settings.shared_secret
            except ObjectDoesNotExist:
                # should not happen, but if organization config settings
                # is not defined the default key will default to being random
                self.key = KeyField.default_callable()
            else:
                self.key = self.generate_key(shared_secret)
        super().save(*args, **kwargs)


class Config(TemplatesVpnMixin, AbstractConfig):
    """
    Concrete Config model
    """
    device = models.OneToOneField('config.Device', on_delete=models.CASCADE)
    templates = SortedManyToManyField('config.Template',
                                      related_name='config_relations',
                                      verbose_name=_('templates'),
                                      base_class=TemplatesThrough,
                                      blank=True,
                                      help_text=_('configuration templates, applied from '
                                                  'first to last'))
    vpn = models.ManyToManyField('config.Vpn',
                                 through='config.VpnClient',
                                 related_name='vpn_relations',
                                 blank=True)

    class Meta(AbstractConfig.Meta):
        abstract = False


class TemplateTag(AbstractTemplateTag):
    """
    openwisp-controller TemplateTag model
    """
    class Meta(AbstractTemplateTag.Meta):
        abstract = False


class TaggedTemplate(AbstractTaggedTemplate):
    """
    openwisp-controller TaggedTemplate model
    """
    tag = models.ForeignKey('config.TemplateTag',
                            related_name='%(app_label)s_%(class)s_items',
                            on_delete=models.CASCADE)

    class Meta(AbstractTaggedTemplate.Meta):
        abstract = False


class Template(ShareableOrgMixin, AbstractTemplate):
    """
    openwisp-controller Template model
    """
    tags = TaggableManager(through='config.TaggedTemplate', blank=True,
                           help_text=_('A comma-separated list of template tags, may be used '
                                       'to ease auto configuration with specific settings (eg: '
                                       '4G, mesh, WDS, VPN, ecc.)'))
    vpn = models.ForeignKey('config.Vpn',
                            verbose_name=_('VPN'),
                            blank=True,
                            null=True,
                            on_delete=models.CASCADE)

    class Meta(AbstractTemplate.Meta):
        abstract = False
        unique_together = (('organization', 'name'), )

    def clean(self):
        self._validate_org_relation('vpn')
        super().clean()


class Vpn(ShareableOrgMixin, AbstractVpn):
    """
    openwisp-controller VPN model
    """
    ca = models.ForeignKey('pki.Ca',
                           verbose_name=_('Certification Authority'),
                           on_delete=models.CASCADE)
    cert = models.ForeignKey('pki.Cert',
                             verbose_name=_('x509 Certificate'),
                             help_text=_('leave blank to create automatically'),
                             blank=True,
                             null=True,
                             on_delete=models.CASCADE)

    class Meta(AbstractVpn.Meta):
        abstract = False

    def clean(self):
        self._validate_org_relation('ca')
        self._validate_org_relation('cert')

    def _auto_create_cert_extra(self, cert):
        """
        sets the organization on the server certificate
        """
        cert.organization = self.organization
        return cert


class VpnClient(AbstractVpnClient):
    """
    m2m through model
    """
    config = models.ForeignKey('config.Config',
                               on_delete=models.CASCADE)
    vpn = models.ForeignKey('config.Vpn',
                            on_delete=models.CASCADE)
    cert = models.OneToOneField('pki.Cert',
                                on_delete=models.CASCADE,
                                blank=True,
                                null=True)

    class Meta(AbstractVpnClient.Meta):
        abstract = False

    def _auto_create_cert_extra(self, cert):
        """
        sets the organization on the created client certificate
        """
        cert.organization = self.config.device.organization
        return cert


class OrganizationConfigSettings(UUIDModel):
    """
    Configuration management settings
    specific to each organization
    """
    organization = models.OneToOneField('openwisp_users.Organization',
                                        verbose_name=_('organization'),
                                        related_name='config_settings',
                                        on_delete=models.CASCADE)
    registration_enabled = models.BooleanField(_('auto-registration enabled'),
                                               default=True,
                                               help_text=_('Whether automatic registration of '
                                                           'devices is enabled or not'))
    shared_secret = KeyField(max_length=32,
                             unique=True,
                             db_index=True,
                             verbose_name=_('shared secret'),
                             help_text=_('used for automatic registration of devices'))

    class Meta:
        verbose_name = _('Configuration management settings')
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.organization.name


class SupernetVPN(models.Model):
    vpn = models.ForeignKey(Vpn,
                            on_delete=models.CASCADE)
    supernet = models.CharField(max_length=20,
                                help_text=_('Supernet block for devices.'),
                                unique=True,
                                null=False,
                                blank=False)
    subnet = models.CharField(max_length=20,
                              help_text=_('Subnet for back to back.'),
                              unique=False,
                              null=False,
                              blank=False)

    class Meta:
        unique_together = ('supernet', 'vpn')
        verbose_name = _('Supernet VPN')
        verbose_name_plural = _('Supernets VPN')


class IpamSubnet(models.Model):
    subnet = models.CharField(max_length=20, unique=True)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE)
    is_used = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('IPAM subnet')
        verbose_name_plural = _('IPAM subnets')


# *********************************************************************************************************************
# *********************************************************************************************************************
# TODO: QUICK AND DIRTY, move later
# *********************************************************************************************************************
# *********************************************************************************************************************
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from ipaddress import IPv4Network


# --------------------------
# ----------- METHODS
# --------------------------

def get_supernet():
    supernet = IpamSubnet.objects.filter(parent=None, is_used=False).first()

    if not supernet:
        raise Exception("No supernet available")

    supernet.is_used = True
    supernet.save()
    return supernet.subnet


def get_subnet_from_supernet(supernet_cidr):
    if not supernet_cidr:
        raise Exception("supernet_cidr cannot be null")

    subnet = IpamSubnet.objects.filter(parent__subnet=supernet_cidr, is_used=False).order_by("id").first()

    if not subnet:
        raise Exception("No subnet available for %s" % supernet_cidr)

    subnet.is_used = True
    subnet.save()
    return subnet.subnet


# --------------------------
# ----------- SIGNALS
# --------------------------
@receiver(post_save, sender=Vpn)
def attribute_supernet(sender, instance, created, **kwargs):
    if created:
        if SupernetVPN.objects.filter(vpn=instance).count() < 1:
            SupernetVPN.objects.create(
                vpn=instance,
                supernet=get_supernet(),
                subnet=""
            )


@receiver(post_save, sender=IpamSubnet)
def split_subnet(sender, instance, created, **kwargs):
    if not created:
        return

    if not instance.parent:
        nw = IPv4Network(instance.subnet)
        for sub in nw.subnets(new_prefix=28):
            IpamSubnet.objects.create(
                subnet=str(sub),
                parent=instance
            )


@receiver(pre_delete, sender=Config)
def clean_subnet(sender, instance, **kwargs):
    try:
        IpamSubnet.objects.filter(subnet=instance.context["Scope_subnet"], is_used=True).update(is_used=False)
    except Exception as err:
        print(err)


@receiver(pre_delete, sender=Vpn)
def clean_supernet(sender, instance, **kwargs):
    # Find the supernet instance
    supernet_vpn = SupernetVPN.objects.get(vpn=instance)
    # Free the subnet contained in the supernet
    IpamSubnet.objects.filter(parent__subnet=supernet_vpn.supernet, is_used=True).update(is_used=False)
    # Free the supernet
    IpamSubnet.objects.filter(subnet=supernet_vpn.supernet, is_used=True).update(is_used=False)


@receiver(pre_delete, sender=VpnClient)
def clean_config(sender, instance, **kwargs):
    context_field = [
        "dhcp_address_start",
        "dhcp_address_limit",
        "lan_interface_address",
        "lan_netmask_dot",
        "lan_network_address",
        "lan_broadcast_address",
        "lan_netmask_cidr",
        "Scope_subnet"
    ]
    config = Config.objects.get(id=instance.config_id)
    subnet_to_free = config.context["Scope_subnet"]
    config_updated = False

    for field in context_field:
        if field in config.context:
            config_updated = True
            del config.context[field]

    if config_updated:
        config.save()
        # Free subnet
        IpamSubnet.objects.filter(subnet=subnet_to_free, is_used=True).update(is_used=False)


# @receiver(post_save, sender=Config)
@receiver(post_save, sender=VpnClient)
def device_attribute_vpn_supernet(sender, instance, created, **kwargs):
    if not created:
        return

    config = instance.config

    if "Scope_subnet" in config.context:
        return

    vpn_supernet = SupernetVPN.objects.get(vpn__id=instance.vpn_id)
    net = IPv4Network(get_subnet_from_supernet(vpn_supernet.supernet))
    subnets = net.subnets(new_prefix=28)
    subnet = next(subnets)

    config.context["dhcp_address_start"] = str(subnet[2]).split(".")[-1]
    config.context["dhcp_address_limit"] = str(subnet.num_addresses - 3)
    config.context["lan_interface_address"] = str(subnet[1])
    config.context["lan_netmask_dot"] = str(subnet.netmask)
    config.context["lan_network_address"] = str(subnet.network_address)
    config.context["lan_broadcast_address"] = str(subnet.broadcast_address)
    config.context["lan_netmask_cidr"] = "28"
    config.context["Scope_subnet"] = str(subnet)
    config.save()
