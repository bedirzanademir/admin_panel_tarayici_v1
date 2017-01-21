#!/usr/bin/perl

#BU YAZILIMI GELİŞTİRMEK ŞARTIYLA DİLEDİĞİNİZ GİBİ PAYLAŞABİLİRSİNİZ
#21.01.2017
#v1.0

use HTTP::Request;
use LWP::UserAgent;

system('cls');
system "color 0a";
print"\n";
print "\t+++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "\t+            Admin Panel Tarayici v1.0          +\n";
print "\t+                Bedir Zana Demir               +\n";
print "\t+          http://instagram.com/bedirzd         +\n";
print "\t+          github: http://goo.gl/1ErLE0         +\n";
print "\t+++++++++++++++++++++++++++++++++++++++++++++++++\n";
print "\n";
print " php, asp, aspx, html, htm, js, cgi, brf, cfm destekler\n\n Hedef girin\n ornek: www.example.com veya www.example.com/path\n-> ";
$site=<STDIN>;
chomp $site;

print "\n";

if ( $site !~ /^http:/ ) {
$site = 'http://' . $site;
}
if ( $site !~ /\/$/ ) {
$site = $site . '/';
}
print "\n";

print " [+] Hedef: $site\n";
print " [+] Admin paneli ve login sayfalari araniyor.. lutfen bekleyin\n\n\n";

@path2=('admin.php','ADMIN.php','login.htm','LOGIN.htm','login.html','LOGIN.html','login/','login.php','LOGIN.php','adm/','admin/','admin/account.html','admin/login.html','admin/login.htm','admin/home.php','admin/controlpanel.html','admin/controlpanel.htm','admin/cp.php','admin/adminLogin.html','admin/adminLogin.htm','admin/admin_login.php','admin/controlpanel.php','admin/admin-login.php','admin-login.php','admin/account.php','admin/admin.php','admin.htm','admin.html','adminitem/','adminitem.php','adminitems/','adminitems.php','administrator/','administrator/login.php','administrator.php','administration/','administration.php','adminLogin/','adminlogin.php','admin_area/admin.php','admin_area/','admin_area/login.php','manager/','manager.php','letmein/','letmein.php','superuser/','superuser.php','access/','access.php','sysadm/','sysadm.php','superman/','supervisor/','panel.php','control/','control.php','member/','member.php','members/','members.php','user/','user.php','cp/','uvpanel/','manage/','manage.php','management/','management.php','signin/','signin.php','log-in/','log-in.php','log_in/','log_in.php','sign_in/','sign_in.php','sign-in/','sign-in.php','users/','users.php','accounts/','accounts.php','wp-login.php','bb-admin/login.php','bb-admin/admin.php','bb-admin/admin.html','administrator/account.php','relogin.htm','relogin.html','check.php','relogin.php','blog/wp-login.php','user/admin.php','users/admin.php','registration/','processlogin.php','checklogin.php','checkuser.php','checkadmin.php','isadmin.php','authenticate.php','authentication.php','auth.php','authuser.php','authadmin.php','cp.php','modelsearch/login.php','moderator.php','moderator/','controlpanel/','controlpanel.php','admincontrol.php','adminpanel.php','fileadmin/','fileadmin.php','sysadmin.php','admin1.php','admin1.html','admin1.htm','admin2.php','admin2.html','yonetim.php','yonetim.html','yonetici.php','yonetici.html','phpmyadmin/','myadmin/','ur-admin.php','ur-admin/','Server.php','Server/','wp-admin/','administr8.php','administr8/','webadmin/','webadmin.php','administratie/','admins/','admins.php','administrivia/','Database_Administration/','useradmin/','sysadmins/','admin1/','system-administration/','administrators/','pgadmin/','directadmin/','staradmin/','ServerAdministrator/','SysAdmin/','administer/','LiveUser_Admin/','sys-admin/','typo3/','panel/','cpanel/','cpanel_file/','platz_login/','rcLogin/','blogindex/','formslogin/','autologin/','support_login/','meta_login/','manuallogin/','simpleLogin/','loginflat/','utility_login/','showlogin/','memlogin/','login-redirect/','sub-login/','wp-login/','login1/','dir-login/','login_db/','xlogin/','smblogin/','customer_login/','UserLogin/','login-us/','acct_login/','bigadmin/','project-admins/','phppgadmin/','pureadmin/','sql-admin/','radmind/','openvpnadmin/','wizmysqladmin/','vadmind/','ezsqliteadmin/','hpwebjetadmin/','newsadmin/','adminpro/','Lotus_Domino_Admin/','bbadmin/','vmailadmin/','Indy_admin/','ccp14admin/','irc-macadmin/','banneradmin/','sshadmin/','phpldapadmin/','macadmin/','administratoraccounts/','admin4_account/','admin4_colon/','radmind-1/','Super-Admin/','AdminTools/','cmsadmin/','SysAdmin2/','globes_admin/','cadmins/','phpSQLiteAdmin/','navSiteAdmin/','server_admin_small/','logo_sysadmin/','power_user/','system_administration/','ss_vms_admin_sm/','bb-admin/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm.php','admin_login.php','panel-administracion/login.php','pages/admin/admin-login.php','pages/admin/','acceso.php','admincp/login.php','admincp/','adminarea/','admincontrol/','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','modules/admin/','administrators.php','siteadmin/','siteadmin.php','adminsite/','kpanel/','vorod/','vorod.php','vorud/','vorud.php','adminpanel/','PSUser/','secure/','webmaster/','webmaster.php','autologin.php','userlogin.php','admin_area.php','cmsadmin.php','security/','usr/','root/','secret/','admin/login.php','admin/adminLogin.php','moderator.html','moderator/login.php','moderator/admin.php','0admin/','0manager/','aadmin/','cgi-bin/login.php','login1.php','login_admin/','login_admin.php','login_out/','login_out.php','login_user.php','loginerror/','loginok/','loginsave/','loginsuper/','loginsuper.php','logout/','logout.php','secrets/','super1/','super1.php','super_index.php','super_login.php','supermanager.php','superman.php','supervise/','supervise/Login.php','super.php','admin','adm','admincp','admcp','cp','modcp','moderatorcp','adminare','admins','cpanel','controlpanel','ccms/','ccms/login.php','ccms/index.php','maintenance/','configuration/','configure/','websvn/','admin/index.php','admin/index.html','admin/cp.html','cp.html','administrator/index.html','administrator/index.php','administrator/login.html','administrator/account.html','administrator.html','moderator/login.html','moderator/admin.html','account.php','account.html','controlpanel.html','admincontrol.html','adminpanel.html','admin1.asp','admin2.asp','yonetim.asp','yonetici.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/home.asp','admin/controlpanel.asp','admin.asp','admin/cp.asp','cp.asp','administrator/index.asp','administrator/login.asp','administrator/account.asp','administrator.asp','login.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','moderator/admin.asp','account.asp','controlpanel.asp','admincontrol.asp','adminpanel.asp','fileadmin.asp','fileadmin.html','administration.html','sysadmin.html','sysadmin.asp','sysadmin/','ur-admin.asp','ur-admin.html','Server.html','Server.asp','administr8.html','administr8.asp','webadmin.asp','webadmin.html','admins.asp','admins.html','administrivia/Database_Administration/WebAdmin/','staradmin/ServerAdministrator/SysAdmin/','administer/LiveUser_Admin/','login-redirect/sub-login/','customer_login/UserLogin/','adminpro/Lotus_Domino_Admin/','vmailadmin/Indy_admin/','radmind-1/Super-Admin/AdminTools/','cmsadmin/SysAdmin2/','server/','database_administration/','siteadmin/login.php','siteadmin/index.php','siteadmin/login.html','admin/admin.html','admin_area/index.php','bb-admin/index.php','admin_area/login.html','admin_area/index.html','admincp/index.asp','admincp/login.asp','admincp/index.html','webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html','nsw/admin/login.php','webadmin/login.php','admin_area/admin.html','bb-admin/index.html','bb-admin/login.html','admin/home.html','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','adminLogin.html','home.html','rcjakar/admin/login.php','adminarea/index.html','adminarea/admin.html','webadmin/index.php','webadmin/admin.php','user.html','modelsearch/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admincontrol/login.html','adm/index.html','adm.html','home.php','adminarea/index.php','adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php','modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2/login.php','admin2/index.php','adm/index.php','admin/admin.asp','admin_area/admin.asp','admin_area/login.asp','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','user.asp','webadmin/index.asp','webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','adminLogin.asp','admin/adminLogin.asp','home.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2/login.asp','admin2/index.asp','adm/index.asp','adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','siteadmin/login.asp','siteadmin/index.asp','ADMIN/','paneldecontrol/','cms/','admon/','ADMON/','administrador/','ADMIN/login.php','panelc/','ADMIN/login.html','adminpanel/PSUser/','0admin/0manager/','cgi-bin/login','login1','login_admin','login_out','login_user','loginsuper','login','logout','super1','super_index','super_login','supermanager','superman','superuser','supervise/Loginsuper','modcp/','administrator.php/','moderator.php/','CMS/','WebAdmin/','joomla/administrator','vpages/admin/admin-login.html','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin_area/admin.cfm','admin_area/login.cfm','siteadmin/login.cfm','siteadmin/index.cfm','admin_area/index.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','admin/controlpanel.cfm','admin.cfm','admin/cp.cfm','cp.cfm','administrator/index.cfm','administrator/login.cfm','nsw/admin/login.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm','administrator/account.cfm','administrator.cfm','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm','login.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm','moderator/admin.cfm','account.cfm','controlpanel.cfm','admincontrol.cfm','acceso.cfm','rcjakar/admin/login.cfm','webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','adminpanel.cfm','user.cfm','panel-administracion/login.cfm','wp-login.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','admin.cfm','adminarea/index.cfm','adminarea/admin.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm','modelsearch/admin.cfm','admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm','admin2/login.cfm','admin2/index.cfm','usuarios/login.cfm','adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm','memberadmin.cfm','administratorlogin.cfm','admin/account.aspx','admin/index.aspx','admin/login.aspx','admin/admin.aspx','admin/account.aspx','admin_area/admin.aspx','admin_area/login.aspx','siteadmin/login.aspx','siteadmin/index.aspx','admin_area/index.aspx','bb-admin/index.aspx','bb-admin/login.aspx','bb-admin/admin.aspx','admin/home.aspx','admin/controlpanel.aspx','admin.aspx','admin/cp.aspx','cp.aspx','administrator/index.aspx','administrator/login.aspx','nsw/admin/login.aspx','webadmin/login.aspx','admin/admin_login.aspx','admin_login.aspx','administrator/account.aspx','administrator.aspx','pages/admin/admin-login.aspx','admin/admin-login.aspx','admin-login.aspx','login.aspx','modelsearch/login.aspx','moderator.aspx','moderator/login.aspx','moderator/admin.aspx','acceso.aspx','account.aspx','controlpanel.aspx','admincontrol.aspx','rcjakar/admin/login.aspx','webadmin.aspx','webadmin/index.aspx','webadmin/admin.aspx','adminpanel.aspx','user.aspx','panel-administracion/login.aspx','wp-login.aspx','adminLogin.aspx','admin/adminLogin.aspx','home.aspx','admin.aspx','adminarea/index.aspx','adminarea/admin.aspx','adminarea/login.aspx','panel-administracion/index.aspx','panel-administracion/admin.aspx','modelsearch/index.aspx','modelsearch/admin.aspx','admincontrol/login.aspx','adm/admloginuser.aspx','admloginuser.aspx','admin2.aspx','admin2/login.aspx','admin2/index.aspx','usuarios/login.aspx','adm/index.aspx','adm.aspx','affiliate.aspx','adm_auth.aspx','memberadmin.aspx','administratorlogin.aspx','admin/account.js','admin/index.js','admin/login.js','admin/admin.js','admin/account.js','admin_area/admin.js','admin_area/login.js','siteadmin/login.js','siteadmin/index.js','admin_area/index.js','bb-admin/index.js','bb-admin/login.js','bb-admin/admin.js','admin/home.js','admin/controlpanel.js','admin.js','admin/cp.js','cp.js','administrator/index.js','administrator/login.js','nsw/admin/login.js','webadmin/login.js','admin/admin_login.js','admin_login.js','administrator/account.js','administrator.js','pages/admin/admin-login.js','admin/admin-login.js','admin-login.js','login.js','modelsearch/login.js','moderator.js','moderator/login.js','moderator/admin.js','account.js','controlpanel.js','admincontrol.js','rcjakar/admin/login.js','webadmin.js','webadmin/index.js','acceso.js','webadmin/admin.js','adminpanel.js','user.js','panel-administracion/login.js','wp-login.js','adminLogin.js','admin/adminLogin.js','home.js','admin.js','adminarea/index.js','adminarea/admin.js','adminarea/login.js','panel-administracion/index.js','panel-administracion/admin.js','modelsearch/index.js','modelsearch/admin.js','admincontrol/login.js','adm/admloginuser.js','admloginuser.js','admin2.js','admin2/login.js','admin2/index.js','usuarios/login.js','adm/index.js','adm.js','affiliate.js','adm_auth.js','memberadmin.js','administratorlogin.js','admin/account.cgi','admin/index.cgi','admin/login.cgi','admin/admin.cgi','admin/account.cgi','admin_area/admin.cgi','admin_area/login.cgi','siteadmin/login.cgi','siteadmin/index.cgi','admin_area/index.cgi','bb-admin/index.cgi','bb-admin/login.cgi','bb-admin/admin.cgi','admin/home.cgi','admin/controlpanel.cgi','admin.cgi','admin/cp.cgi','cp.cgi','administrator/index.cgi','administrator/login.cgi','nsw/admin/login.cgi','webadmin/login.cgi','admin/admin_login.cgi','admin_login.cgi','administrator/account.cgi','administrator.cgi','pages/admin/admin-login.cgi','admin/admin-login.cgi','admin-login.cgi','login.cgi','modelsearch/login.cgi','moderator.cgi','moderator/login.cgi','moderator/admin.cgi','account.cgi','controlpanel.cgi','admincontrol.cgi','rcjakar/admin/login.cgi','webadmin.cgi','webadmin/index.cgi','acceso.cgi','webadmin/admin.cgi','adminpanel.cgi','user.cgi','panel-administracion/login.cgi','wp-login.cgi','adminLogin.cgi','admin/adminLogin.cgi','home.cgi','admin.cgi','adminarea/index.cgi','adminarea/admin.cgi','adminarea/login.cgi','panel-administracion/index.cgi','panel-administracion/admin.cgi','modelsearch/index.cgi','modelsearch/admin.cgi','admincontrol/login.cgi','adm/admloginuser.cgi','admloginuser.cgi','admin2.cgi','admin2/login.cgi','admin2/index.cgi','usuarios/login.cgi','adm/index.cgi','adm.cgi','affiliate.cgi','adm_auth.cgi','memberadmin.cgi','administratorlogin.cgi','admin/account.brf','admin/index.brf','admin/login.brf','admin/admin.brf','admin/account.brf','admin_area/admin.brf','admin_area/login.brf','siteadmin/login.brf','siteadmin/index.brf','admin_area/index.brf','bb-admin/index.brf','bb-admin/login.brf','bb-admin/admin.brf','admin/home.brf','admin/controlpanel.brf','admin.brf','admin/cp.brf','cp.brf','administrator/index.brf','administrator/login.brf','nsw/admin/login.brf','webadmin/login.brf','admin/admin_login.brf','admin_login.brf','administrator/account.brf','administrator.brf','acceso.brf','pages/admin/admin-login.brf','admin/admin-login.brf','admin-login.brf','login.brf','modelsearch/login.brf','moderator.brf','moderator/login.brf','moderator/admin.brf','account.brf','controlpanel.brf','admincontrol.brf','rcjakar/admin/login.brf','webadmin.brf','webadmin/index.brf','webadmin/admin.brf','adminpanel.brf','user.brf','panel-administracion/login.brf','wp-login.brf','adminLogin.brf','admin/adminLogin.brf','home.brf','admin.brf','adminarea/index.brf','adminarea/admin.brf','adminarea/login.brf','panel-administracion/index.brf','panel-administracion/admin.brf','modelsearch/index.brf','modelsearch/admin.brf','admincontrol/login.brf','adm/admloginuser.brf','admloginuser.brf','admin2.brf','admin2/login.brf','admin2/index.brf','usuarios/login.brf','adm/index.brf','adm.brf','affiliate.brf','adm_auth.brf','memberadmin.brf','administratorlogin.brf', 'giris.php', 'giris.asp', 'giris.aspx', 'giris.html'
);

@sonuc=();
$dongus=0;
$donguy=0;
$donguk=0;
$sayma=0;
print "  $donguy% tamamlandi..\n";
foreach $ways(@path2){

$final=$site.$ways;

$dongus=$dongus+1;
if($dongus==$donguk+43){
$donguy=$donguy+5;
$donguk=$donguk+43;
print "  $donguy% tamamlandi..\n";
}
my $req=HTTP::Request->new(GET=>$final);
my $ua=LWP::UserAgent->new();
$ua->timeout(30);
my $response=$ua->request($req);

if($response->content =~ /Username/ ||
$response->content =~ /Password/ ||
$response->content =~ /loginform/ ||
$response->content =~ /user_login/ ||
$response->content =~ /user_pass/ ||
$response->content =~ /username/ ||
$response->content =~ /password/ ||
$response->content =~ /user/ ||
$response->content =~ /pass/ ||
$response->content =~ /kadi/ ||
$response->content =~ /sifre/ ||
$response->content =~ /kullaniciadi/ ||
$response->content =~ /USERNAME/ ||
$response->content =~ /PASSWORD/ ||
$response->content =~ /Wachtwoord/ ||
$response->content =~ /Senha/ ||
$response->content =~ /senha/ ||
$response->content =~ /Personal/ ||
$response->content =~ /Usuario/ ||
$response->content =~ /Clave/ ||
$response->content =~ /Usager/ ||
$response->content =~ /usager/ ||
$response->content =~ /Sing/ ||
$response->content =~ /passe/ ||
$response->content =~ /P\/W/ || 
$response->content =~ /Admin Password/
){
$sayma=1;
push(@sonuc, $final);
}
}

if($sayma==1){
print "________________________________________________________________________";
print "\n\n  Tarama tamamlandi. Tespit edilen sayfalar\n\n";
foreach $listele(@sonuc){
print "-> $listele\n";
}
print "\n________________________________________________________________________\n\n";
}else{
print "\n\n Tarama tamamlandi fakat hicbir sonuc bulunamadi.\n\n";
}
