/* Time Display — 主逻辑
   从 timedisplay.html 内联 <script> 抽出，内容未改动 */

if ('serviceWorker' in navigator) {
  // 已有 SW 接管时，若检测到新的 SW 接管，自动刷新一次拿到最新资源（防止旧缓存顶住更新）
  const hadController = !!navigator.serviceWorker.controller;
  let refreshed = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!hadController || refreshed) return;
    refreshed = true;
    location.reload();
  });
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' })
      .then(reg => {
        console.log('[PWA] SW registered:', reg.scope);
        reg.update();
      })
      .catch(err => console.log('[PWA] SW failed:', err));
  });
}
const heavenlyStems = ['甲','乙','丙','丁','戊','己','庚','辛','壬','癸'];
const earthlyBranches = ['子','丑','寅','卯','辰','巳','午','未','申','酉','戌','亥'];
const zodiacAnimals = ['鼠','牛','虎','兔','龙','蛇','马','羊','猴','鸡','狗','猪'];
const moonPhases = ['New Moon','Waxing Crescent','First Quarter','Waxing Gibbous','Full Moon','Waning Gibbous','Last Quarter','Waning Crescent'];
const moonPhasesZh = ['新月','娥眉月','上弦月','盈凸月','满月','亏凸月','下弦月','残月'];

function getGanzhiYear(y){ return heavenlyStems[(y-4)%10]+earthlyBranches[(y-4)%12]; }
function getZodiac(y){ return zodiacAnimals[(y-4)%12]; }
function getGanzhiMonth(y,m){
    const msb=[2,14,26,38,50,62,74,86,98,110][(y-4)%10]%10;
    return heavenlyStems[(msb+m-1)%10]+earthlyBranches[(m+1)%12];
}
function getGanzhiDay(d){
    const y=d.getFullYear(),m=d.getMonth()+1,day=d.getDate();
    const c=Math.floor(y/100),y2=y%100;
    let g=m===1||m===2?4*c+Math.floor(c/4)+5*y2+Math.floor(y2/4)+Math.floor(3*(m+12)/5)+day-3:4*c+Math.floor(c/4)+5*y2+Math.floor(y2/4)+Math.floor(3*m/5)+day-3;
    return heavenlyStems[(g%10+10)%10]+earthlyBranches[(g%12+12)%12];
}
function getGanzhiHour(h){ return earthlyBranches[Math.floor((h+1)/2)%12]; }
function getWeekNumber(d){
    const dt=new Date(Date.UTC(d.getFullYear(),d.getMonth(),d.getDate()));
    const dn=dt.getUTCDay()||7;
    dt.setUTCDate(dt.getUTCDate()+4-dn);
    return Math.ceil((((dt-new Date(Date.UTC(dt.getUTCFullYear(),0,1)))/86400000)+1)/7);
}
function getJulianDay(d){
    const y=d.getFullYear(),m=d.getMonth()+1,day=d.getDate();
    const a=Math.floor((14-m)/12),yy=y+4800-a,mm=m+12*a-3;
    return day+Math.floor((153*mm+2)/5)+365*yy+Math.floor(yy/4)-Math.floor(yy/100)+Math.floor(yy/400)-32045;
}
function getDayOfYear(d){ const s=new Date(d.getFullYear(),0,0); return Math.floor((d-s)/86400000); }
function getMoonPhase(d){
    let year=d.getFullYear(),month=d.getMonth()+1,day=d.getDate();
    let c,e,jd,b;
    if(month<3){year--;month+=12;}
    c=365.25*year;e=30.6*month;jd=c+e+day-694039.09;jd/=29.5305882;b=parseInt(jd);jd-=b;
    return Math.round(jd*8)%8;
}
function getSunriseSunset(lat,lon,date){
    const dayOfYear=Math.floor((date-new Date(date.getFullYear(),0,0))/86400000);
    const pi=Math.PI,rad=pi/180;
    const latRad=lat*rad;
    const declination=0.4093*Math.sin(2*pi*(284+dayOfYear)/365);
    const hourAngle=Math.acos(-Math.tan(latRad)*Math.tan(declination));
    const sunrise=12-(hourAngle*180/pi)/15;
    const sunset=12+(hourAngle*180/pi)/15;
    const sunriseH=Math.floor(sunrise),sunriseM=Math.floor((sunrise-sunriseH)*60);
    const sunsetH=Math.floor(sunset),sunsetM=Math.floor((sunset-sunsetH)*60);
    return {rise:`${String(sunriseH).padStart(2,'0')}:${String(sunriseM).padStart(2,'0')}`,set:`${String(sunsetH).padStart(2,'0')}:${String(sunsetM).padStart(2,'0')}`};
}

const i18n={
    en:{
        lang_label:'Language',ganzhi_label:'Ganzhi Calendar',ganzhi_off:'OFF',ganzhi_on:'ON',
        week_label:'Week Number',week_off:'OFF',week_on:'ON',
        julian_label:'Julian Day',julian_off:'OFF',julian_on:'ON',
        dayofyear_label:'Day of Year',doy_off:'OFF',doy_on:'ON',
        moon_label:'Moon Phase',moon_off:'OFF',moon_on:'ON',
        sun_label:'Sunrise / Sunset',sun_off:'OFF',sun_on:'ON',
        timezone_label:'Timezone',tzshow_label:'Show Timezone',tz_off:'OFF',tz_on:'ON',
        seconds_label:'Show Seconds',seconds_off:'OFF',seconds_on:'ON',
        colon_label:'Blinking Colon',colon_off:'OFF',colon_on:'ON',
        '24h_label':'24-Hour Format','24h_off':'OFF','24h_on':'ON',
        stopwatch_label:'Stopwatch',sw_off:'OFF',sw_on:'ON',
        timer_label:'Countdown Timer',timer_off:'OFF',timer_on:'ON',
        color_label:'Accent Color',fullscreen_label:'Fullscreen',fs_off:'OFF',fs_on:'ON',
        fmt_label:'Date Format',size_label:'Clock Size',theme_label:'Theme',
        world_label:'World Clock',add_city:'+ Add City',share_label:'Share',ts_label:'Timestamp',
        label:'Year / Month / Date / Day / Hour / Minute / Second',
        months:['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'],
        days:['SUN','MON','TUE','WED','THU','FRI','SAT']
    },
    zh:{
        lang_label:'语言',ganzhi_label:'干支纪年',ganzhi_off:'关闭',ganzhi_on:'开启',
        week_label:'周数',week_off:'关闭',week_on:'开启',
        julian_label:'儒略日',julian_off:'关闭',julian_on:'开启',
        dayofyear_label:'年内第几天',doy_off:'关闭',doy_on:'开启',
        moon_label:'月相',moon_off:'关闭',moon_on:'开启',
        sun_label:'日出日落',sun_off:'关闭',sun_on:'开启',
        timezone_label:'时区',tzshow_label:'显示时区',tz_off:'关闭',tz_on:'开启',
        seconds_label:'显示秒数',seconds_off:'关闭',seconds_on:'开启',
        colon_label:'闪烁冒号',colon_off:'关闭',colon_on:'开启',
        '24h_label':'24小时制','24h_off':'关闭','24h_on':'开启',
        stopwatch_label:'秒表',sw_off:'关闭',sw_on:'开启',
        timer_label:'倒计时',timer_off:'关闭',timer_on:'开启',
        color_label:'强调色',fullscreen_label:'全屏',fs_off:'关闭',fs_on:'开启',
        fmt_label:'日期格式',size_label:'时钟大小',theme_label:'主题',
        world_label:'世界时钟',add_city:'+ 添加城市',share_label:'分享',ts_label:'时间戳',
        label:'年 / 月 / 日 / 星期 / 时 / 分 / 秒',
        months:['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月'],
        days:['周日','周一','周二','周三','周四','周五','周六']
    },
    ja:{
        lang_label:'言語',ganzhi_label:'干支暦',ganzhi_off:'OFF',ganzhi_on:'ON',
        week_label:'週番号',week_off:'OFF',week_on:'ON',
        julian_label:'ユリウス日',julian_off:'OFF',julian_on:'ON',
        dayofyear_label:'年間通算日',doy_off:'OFF',doy_on:'ON',
        moon_label:'月相',moon_off:'OFF',moon_on:'ON',
        sun_label:'日の出/日の入',sun_off:'OFF',sun_on:'ON',
        timezone_label:'タイムゾーン',tzshow_label:'タイムゾーン表示',tz_off:'OFF',tz_on:'ON',
        seconds_label:'秒表示',seconds_off:'OFF',seconds_on:'ON',
        colon_label:'点滅コロン',colon_off:'OFF',colon_on:'ON',
        '24h_label':'24時間制','24h_off':'OFF','24h_on':'ON',
        stopwatch_label:'ストップウォッチ',sw_off:'OFF',sw_on:'ON',
        timer_label:'タイマー',timer_off:'OFF',timer_on:'ON',
        color_label:'アクセント色',fullscreen_label:'全画面',fs_off:'OFF',fs_on:'ON',
        fmt_label:'日付形式',size_label:'時計サイズ',theme_label:'テーマ',
        world_label:'世界時計',add_city:'+ 都市追加',share_label:'共有',ts_label:'タイムスタンプ',
        label:'年 / 月 / 日 / 曜日 / 時 / 分 / 秒',
        months:['1月','2月','3月','4月','5月','6月','7月','8月','9月','10月','11月','12月'],
        days:['日','月','火','水','木','金','土']
    },
    ko:{
        lang_label:'언어',ganzhi_label:'간지력',ganzhi_off:'OFF',ganzhi_on:'ON',
        week_label:'주 번호',week_off:'OFF',week_on:'ON',
        julian_label:'줄리안 일',julian_off:'OFF',julian_on:'ON',
        dayofyear_label:'연중 일수',doy_off:'OFF',doy_on:'ON',
        moon_label:'월상',moon_off:'OFF',moon_on:'ON',
        sun_label:'일출/일몰',sun_off:'OFF',sun_on:'ON',
        timezone_label:'시간대',tzshow_label:'시간대 표시',tz_off:'OFF',tz_on:'ON',
        seconds_label:'초 표시',seconds_off:'OFF',seconds_on:'ON',
        colon_label:'깜빡이는 콜론',colon_off:'OFF',colon_on:'ON',
        '24h_label':'24시간제','24h_off':'OFF','24h_on':'ON',
        stopwatch_label:'스톱워치',sw_off:'OFF',sw_on:'ON',
        timer_label:'타이머',timer_off:'OFF',timer_on:'ON',
        color_label:'강조색',fullscreen_label:'전체화면',fs_off:'OFF',fs_on:'ON',
        fmt_label:'날짜 형식',size_label:'시계 크기',theme_label:'테마',
        world_label:'세계 시계',add_city:'+ 도시 추가',share_label:'공유',ts_label:'타임스탬프',
        label:'년 / 월 / 일 / 요일 / 시 / 분 / 초',
        months:['1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월'],
        days:['일','월','화','수','목','금','토']
    },
    fr:{
        lang_label:'Langue',ganzhi_label:'Calendrier Ganzhi',ganzhi_off:'OFF',ganzhi_on:'ON',
        week_label:'Numero Semaine',week_off:'OFF',week_on:'ON',
        julian_label:'Jour Julien',julian_off:'OFF',julian_on:'ON',
        dayofyear_label:'Jour de l Annee',doy_off:'OFF',doy_on:'ON',
        moon_label:'Phase Lune',moon_off:'OFF',moon_on:'ON',
        sun_label:'Lever/Coucher Soleil',sun_off:'OFF',sun_on:'ON',
        timezone_label:'Fuseau Horaire',tzshow_label:'Afficher Fuseau',tz_off:'OFF',tz_on:'ON',
        seconds_label:'Afficher Secondes',seconds_off:'OFF',seconds_on:'ON',
        colon_label:'Deux Points Clignotant',colon_off:'OFF',colon_on:'ON',
        '24h_label':'Format 24h','24h_off':'OFF','24h_on':'ON',
        stopwatch_label:'Chronometre',sw_off:'OFF',sw_on:'ON',
        timer_label:'Minuteur',timer_off:'OFF',timer_on:'ON',
        color_label:'Couleur Accent',fullscreen_label:'Plein Ecran',fs_off:'OFF',fs_on:'ON',
        fmt_label:'Format Date',size_label:'Taille Horloge',theme_label:'Theme',
        world_label:'Horloge Mondiale',add_city:'+ Ajouter',share_label:'Partager',ts_label:'Horodatage',
        label:'Annee / Mois / Date / Jour / Heure / Minute / Seconde',
        months:['JAN','FEV','MAR','AVR','MAI','JUN','JUL','AOU','SEP','OCT','NOV','DEC'],
        days:['DIM','LUN','MAR','MER','JEU','VEN','SAM']
    },
    de:{
        lang_label:'Sprache',ganzhi_label:'Ganzhi-Kalender',ganzhi_off:'AUS',ganzhi_on:'AN',
        week_label:'Wochennummer',week_off:'AUS',week_on:'AN',
        julian_label:'Julianischer Tag',julian_off:'AUS',julian_on:'AN',
        dayofyear_label:'Tag des Jahres',doy_off:'AUS',doy_on:'AN',
        moon_label:'Mondphase',moon_off:'AUS',moon_on:'AN',
        sun_label:'Sonnenauf/untergang',sun_off:'AUS',sun_on:'AN',
        timezone_label:'Zeitzone',tzshow_label:'Zeitzone Anzeigen',tz_off:'AUS',tz_on:'AN',
        seconds_label:'Sekunden Anzeigen',seconds_off:'AUS',seconds_on:'AN',
        colon_label:'Blinkender Doppelpunkt',colon_off:'AUS',colon_on:'AN',
        '24h_label':'24-Stunden-Format','24h_off':'AUS','24h_on':'AN',
        stopwatch_label:'Stoppuhr',sw_off:'AUS',sw_on:'AN',
        timer_label:'Timer',timer_off:'AUS',timer_on:'AN',
        color_label:'Akzentfarbe',fullscreen_label:'Vollbild',fs_off:'AUS',fs_on:'AN',
        fmt_label:'Datumsformat',size_label:'Uhr Groesse',theme_label:'Thema',
        world_label:'Weltuhr',add_city:'+ Stadt',share_label:'Teilen',ts_label:'Zeitstempel',
        label:'Jahr / Monat / Datum / Tag / Stunde / Minute / Sekunde',
        months:['JAN','FEB','MAR','APR','MAI','JUN','JUL','AUG','SEP','OKT','NOV','DEZ'],
        days:['SO','MO','DI','MI','DO','FR','SA']
    },
    es:{
        lang_label:'Idioma',ganzhi_label:'Calendario Ganzhi',ganzhi_off:'OFF',ganzhi_on:'ON',
        week_label:'Numero Semana',week_off:'OFF',week_on:'ON',
        julian_label:'Dia Juliano',julian_off:'OFF',julian_on:'ON',
        dayofyear_label:'Dia del Ano',doy_off:'OFF',doy_on:'ON',
        moon_label:'Fase Lunar',moon_off:'OFF',moon_on:'ON',
        sun_label:'Amanecer/Atardecer',sun_off:'OFF',sun_on:'ON',
        timezone_label:'Zona Horaria',tzshow_label:'Mostrar Zona',tz_off:'OFF',tz_on:'ON',
        seconds_label:'Mostrar Segundos',seconds_off:'OFF',seconds_on:'ON',
        colon_label:'Dos Puntos Parpadeante',colon_off:'OFF',colon_on:'ON',
        '24h_label':'Formato 24h','24h_off':'OFF','24h_on':'ON',
        stopwatch_label:'Cronometro',sw_off:'OFF',sw_on:'ON',
        timer_label:'Temporizador',timer_off:'OFF',timer_on:'ON',
        color_label:'Color Acento',fullscreen_label:'Pantalla Completa',fs_off:'OFF',fs_on:'ON',
        fmt_label:'Formato Fecha',size_label:'Tamano Reloj',theme_label:'Tema',
        world_label:'Reloj Mundial',add_city:'+ Ciudad',share_label:'Compartir',ts_label:'Marca Temporal',
        label:'Ano / Mes / Fecha / Dia / Hora / Minuto / Segundo',
        months:['ENE','FEB','MAR','ABR','MAY','JUN','JUL','AGO','SEP','OCT','NOV','DIC'],
        days:['DOM','LUN','MAR','MIE','JUE','VIE','SAB']
    },
    ru:{
        lang_label:'Язык',ganzhi_label:'Календарь Ганьчжи',ganzhi_off:'ВЫКЛ',ganzhi_on:'ВКЛ',
        week_label:'Номер Недели',week_off:'ВЫКЛ',week_on:'ВКЛ',
        julian_label:'Юлианская Дата',julian_off:'ВЫКЛ',julian_on:'ВКЛ',
        dayofyear_label:'День Года',doy_off:'ВЫКЛ',doy_on:'ВКЛ',
        moon_label:'Фаза Луны',moon_off:'ВЫКЛ',moon_on:'ВКЛ',
        sun_label:'Восход/Закат',sun_off:'ВЫКЛ',sun_on:'ВКЛ',
        timezone_label:'Часовой Пояс',tzshow_label:'Показать Пояс',tz_off:'ВЫКЛ',tz_on:'ВКЛ',
        seconds_label:'Показать Секунды',seconds_off:'ВЫКЛ',seconds_on:'ВКЛ',
        colon_label:'Мигающее Двоеточие',colon_off:'ВЫКЛ',colon_on:'ВКЛ',
        '24h_label':'24-часовой Формат','24h_off':'ВЫКЛ','24h_on':'ВКЛ',
        stopwatch_label:'Секундомер',sw_off:'ВЫКЛ',sw_on:'ВКЛ',
        timer_label:'Таймер',timer_off:'ВЫКЛ',timer_on:'ВКЛ',
        color_label:'Цвет Акцента',fullscreen_label:'Полный Экран',fs_off:'ВЫКЛ',fs_on:'ВКЛ',
        fmt_label:'Формат Даты',size_label:'Размер Часов',theme_label:'Тема',
        world_label:'Мировые Часы',add_city:'+ Город',share_label:'Поделиться',ts_label:'Метка Времени',
        label:'Год / Месяц / Дата / День / Час / Минута / Секунда',
        months:['ЯНВ','ФЕВ','МАР','АПР','МАЙ','ИЮН','ИЮЛ','АВГ','СЕН','ОКТ','НОЯ','ДЕК'],
        days:['ВС','ПН','ВТ','СР','ЧТ','ПТ','СБ']
    },
    ar:{
        lang_label:'اللغة',ganzhi_label:'التقويم الصيني',ganzhi_off:'إيقاف',ganzhi_on:'تشغيل',
        week_label:'رقم الأسبوع',week_off:'إيقاف',week_on:'تشغيل',
        julian_label:'اليوم اليوليوسي',julian_off:'إيقاف',julian_on:'تشغيل',
        dayofyear_label:'يوم السنة',doy_off:'إيقاف',doy_on:'تشغيل',
        moon_label:'طور القمر',moon_off:'إيقاف',moon_on:'تشغيل',
        sun_label:'الشروق/الغروب',sun_off:'إيقاف',sun_on:'تشغيل',
        timezone_label:'المنطقة الزمنية',tzshow_label:'عرض المنطقة',tz_off:'إيقاف',tz_on:'تشغيل',
        seconds_label:'عرض الثواني',seconds_off:'إيقاف',seconds_on:'تشغيل',
        colon_label:'نقطتان وامضتان',colon_off:'إيقاف',colon_on:'تشغيل',
        '24h_label':'تنسيق 24 ساعة','24h_off':'إيقاف','24h_on':'تشغيل',
        stopwatch_label:'ساعة التوقيف',sw_off:'إيقاف',sw_on:'تشغيل',
        timer_label:'المؤقت',timer_off:'إيقاف',timer_on:'تشغيل',
        color_label:'لون التمييز',fullscreen_label:'ملء الشاشة',fs_off:'إيقاف',fs_on:'تشغيل',
        fmt_label:'تنسيق التاريخ',size_label:'حجم الساعة',theme_label:'السمة',
        world_label:'ساعة العالم',add_city:'+ مدينة',share_label:'مشاركة',ts_label:'الطابع الزمني',
        label:'سنة / شهر / تاريخ / يوم / ساعة / دقيقة / ثانية',
        months:['ينا','فبر','مار','أبر','ماي','يون','يول','أغس','سبت','أكت','نوف','ديس'],
        days:['أح','إث','ثل','أر','خم','جم','سب']
    }
};

let currentLang='en',ganzhiEnabled=false,weekEnabled=false,julianEnabled=false,doyEnabled=false;
let moonEnabled=false,sunEnabled=false,tzDisplayEnabled=false,secondsEnabled=true,colonEnabled=true;
let format24h=true,swEnabled=false,timerEnabled=false,fsEnabled=false;
let selectedTimezone='local',accentColor='black';
let swRunning=false,swStartTime=0,swElapsed=0,swInterval=null;
let timerRunning=false,timerRemaining=0,timerInterval=null;
let dateFormat='ymd';
let worldClocks=[];

const menuBtn=document.getElementById('menuBtn'),sidebar=document.getElementById('sidebar'),sidebarOverlay=document.getElementById('sidebarOverlay');
const ganzhiToggle=document.getElementById('ganzhiToggle'),ganzhiTrack=document.getElementById('ganzhiTrack'),ganzhiDisplay=document.getElementById('ganzhi');
const weekToggle=document.getElementById('weekToggle'),weekTrack=document.getElementById('weekTrack'),weekDisplay=document.getElementById('week');
const julianToggle=document.getElementById('julianToggle'),julianTrack=document.getElementById('julianTrack'),julianDisplay=document.getElementById('julian');
const doyToggle=document.getElementById('doyToggle'),doyTrack=document.getElementById('doyTrack'),doyDisplay=document.getElementById('doy');
const moonToggle=document.getElementById('moonToggle'),moonTrack=document.getElementById('moonTrack'),moonDisplay=document.getElementById('moon');
const sunToggle=document.getElementById('sunToggle'),sunTrack=document.getElementById('sunTrack'),sunDisplay=document.getElementById('sun');
const tzToggle=document.getElementById('tzToggle'),tzTrack=document.getElementById('tzTrack'),tzDisplayEl=document.getElementById('tz');
const timezoneSelect=document.getElementById('timezoneSelect');
const secondsToggle=document.getElementById('secondsToggle'),secondsTrack=document.getElementById('secondsTrack');
const colonToggle=document.getElementById('colonToggle'),colonTrack=document.getElementById('colonTrack');
const formatToggle=document.getElementById('formatToggle'),formatTrack=document.getElementById('formatTrack');
const swToggle=document.getElementById('swToggle'),swTrack=document.getElementById('swTrack');
const swDisplay=document.getElementById('swDisplay'),swControls=document.getElementById('swControls');
const swStart=document.getElementById('swStart'),swStop=document.getElementById('swStop'),swReset=document.getElementById('swReset');
const timerToggle=document.getElementById('timerToggle'),timerTrack=document.getElementById('timerTrack');
const timerDisplay=document.getElementById('timerDisplay'),timerControls=document.getElementById('timerControls');
const tmStart=document.getElementById('tmStart'),tmPause=document.getElementById('tmPause'),tmReset=document.getElementById('tmReset');
const colorSelect=document.getElementById('colorSelect');
const fsToggle=document.getElementById('fsToggle'),fsTrack=document.getElementById('fsTrack');
const sizeSlider=document.getElementById('sizeSlider');
const worldClockSelect=document.getElementById('worldClockSelect');
const worldClockList=document.getElementById('worldClockList');

function openSidebar(){ 
    menuBtn.classList.add('active');
    menuBtn.style.opacity = '0';
    menuBtn.style.pointerEvents = 'none';
    sidebar.classList.add('active');
    sidebarOverlay.classList.add('active'); 
}

function closeSidebar(){ 
    menuBtn.classList.remove('active');
    menuBtn.style.opacity = '1';
    menuBtn.style.pointerEvents = 'auto';
    sidebar.classList.remove('active');
    sidebarOverlay.classList.remove('active'); 
}
menuBtn.addEventListener('click',()=>{ sidebar.classList.contains('active')?closeSidebar():openSidebar(); });
sidebarOverlay.addEventListener('click',closeSidebar);

document.querySelectorAll('.lang-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
        document.querySelectorAll('.lang-btn').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');currentLang=btn.dataset.lang;
        updateI18n();updateClock();updateWorldClocks();
    });
});

function updateI18n(){
    const t=i18n[currentLang];
    document.querySelectorAll('[data-i18n]').forEach(el=>{ const key=el.dataset.i18n;if(t[key])el.textContent=t[key]; });
    ganzhiToggle.querySelector('.toggle-label').textContent=ganzhiEnabled?t.ganzhi_on:t.ganzhi_off;
    weekToggle.querySelector('.toggle-label').textContent=weekEnabled?t.week_on:t.week_off;
    julianToggle.querySelector('.toggle-label').textContent=julianEnabled?t.julian_on:t.julian_off;
    doyToggle.querySelector('.toggle-label').textContent=doyEnabled?t.doy_on:t.doy_off;
    moonToggle.querySelector('.toggle-label').textContent=moonEnabled?t.moon_on:t.moon_off;
    sunToggle.querySelector('.toggle-label').textContent=sunEnabled?t.sun_on:t.sun_off;
    tzToggle.querySelector('.toggle-label').textContent=tzDisplayEnabled?t.tz_on:t.tz_off;
    secondsToggle.querySelector('.toggle-label').textContent=secondsEnabled?t.seconds_on:t.seconds_off;
    colonToggle.querySelector('.toggle-label').textContent=colonEnabled?t.colon_on:t.colon_off;
    formatToggle.querySelector('.toggle-label').textContent=format24h?t['24h_on']:t['24h_off'];
    swToggle.querySelector('.toggle-label').textContent=swEnabled?t.sw_on:t.sw_off;
    timerToggle.querySelector('.toggle-label').textContent=timerEnabled?t.timer_on:t.timer_off;
    fsToggle.querySelector('.toggle-label').textContent=fsEnabled?t.fs_on:t.fs_off;
}

ganzhiToggle.addEventListener('click',()=>{ ganzhiEnabled=!ganzhiEnabled;ganzhiTrack.classList.toggle('on',ganzhiEnabled);const t=i18n[currentLang];ganzhiToggle.querySelector('.toggle-label').textContent=ganzhiEnabled?t.ganzhi_on:t.ganzhi_off;ganzhiDisplay.classList.toggle('show',ganzhiEnabled);updateClock(); });
weekToggle.addEventListener('click',()=>{ weekEnabled=!weekEnabled;weekTrack.classList.toggle('on',weekEnabled);const t=i18n[currentLang];weekToggle.querySelector('.toggle-label').textContent=weekEnabled?t.week_on:t.week_off;weekDisplay.classList.toggle('show',weekEnabled);updateClock(); });
julianToggle.addEventListener('click',()=>{ julianEnabled=!julianEnabled;julianTrack.classList.toggle('on',julianEnabled);const t=i18n[currentLang];julianToggle.querySelector('.toggle-label').textContent=julianEnabled?t.julian_on:t.julian_off;julianDisplay.classList.toggle('show',julianEnabled);updateClock(); });
doyToggle.addEventListener('click',()=>{ doyEnabled=!doyEnabled;doyTrack.classList.toggle('on',doyEnabled);const t=i18n[currentLang];doyToggle.querySelector('.toggle-label').textContent=doyEnabled?t.doy_on:t.doy_off;doyDisplay.classList.toggle('show',doyEnabled);updateClock(); });
moonToggle.addEventListener('click',()=>{ moonEnabled=!moonEnabled;moonTrack.classList.toggle('on',moonEnabled);const t=i18n[currentLang];moonToggle.querySelector('.toggle-label').textContent=moonEnabled?t.moon_on:t.moon_off;moonDisplay.classList.toggle('show',moonEnabled);updateClock(); });
sunToggle.addEventListener('click',()=>{ sunEnabled=!sunEnabled;sunTrack.classList.toggle('on',sunEnabled);const t=i18n[currentLang];sunToggle.querySelector('.toggle-label').textContent=sunEnabled?t.sun_on:t.sun_off;sunDisplay.classList.toggle('show',sunEnabled);updateClock(); });
tzToggle.addEventListener('click',()=>{ tzDisplayEnabled=!tzDisplayEnabled;tzTrack.classList.toggle('on',tzDisplayEnabled);const t=i18n[currentLang];tzToggle.querySelector('.toggle-label').textContent=tzDisplayEnabled?t.tz_on:t.tz_off;tzDisplayEl.classList.toggle('show',tzDisplayEnabled);updateClock(); });
secondsToggle.addEventListener('click',()=>{ secondsEnabled=!secondsEnabled;secondsTrack.classList.toggle('on',secondsEnabled);const t=i18n[currentLang];secondsToggle.querySelector('.toggle-label').textContent=secondsEnabled?t.seconds_on:t.seconds_off;updateClock(); });
colonToggle.addEventListener('click',()=>{ colonEnabled=!colonEnabled;colonTrack.classList.toggle('on',colonEnabled);const t=i18n[currentLang];colonToggle.querySelector('.toggle-label').textContent=colonEnabled?t.colon_on:t.colon_off;updateClock(); });
formatToggle.addEventListener('click',()=>{ format24h=!format24h;formatTrack.classList.toggle('on',format24h);const t=i18n[currentLang];formatToggle.querySelector('.toggle-label').textContent=format24h?t['24h_on']:t['24h_off'];updateClock();updateWorldClocks(); });

swToggle.addEventListener('click',()=>{
    swEnabled=!swEnabled;swTrack.classList.toggle('on',swEnabled);const t=i18n[currentLang];swToggle.querySelector('.toggle-label').textContent=swEnabled?t.sw_on:t.sw_off;
    swDisplay.classList.toggle('show',swEnabled);swControls.classList.toggle('show',swEnabled);
    if(!swEnabled&&swRunning){ swRunning=false;clearInterval(swInterval); }
});
swStart.addEventListener('click',()=>{ if(!swRunning){ swRunning=true;swStartTime=Date.now()-swElapsed;swInterval=setInterval(()=>{swElapsed=Date.now()-swStartTime;updateStopwatch();},10); } });
swStop.addEventListener('click',()=>{ if(swRunning){ swRunning=false;clearInterval(swInterval); } });
swReset.addEventListener('click',()=>{ swRunning=false;clearInterval(swInterval);swElapsed=0;updateStopwatch(); });
function updateStopwatch(){
    const m=Math.floor(swElapsed/60000),s=Math.floor((swElapsed%60000)/1000),ms=Math.floor((swElapsed%1000)/10);
    document.getElementById('swMin').textContent=String(m).padStart(2,'0');
    document.getElementById('swSec').textContent=String(s).padStart(2,'0');
    document.getElementById('swMs').textContent=String(ms).padStart(2,'0');
}

timerToggle.addEventListener('click',()=>{
    timerEnabled=!timerEnabled;timerTrack.classList.toggle('on',timerEnabled);const t=i18n[currentLang];timerToggle.querySelector('.toggle-label').textContent=timerEnabled?t.timer_on:t.timer_off;
    timerDisplay.classList.toggle('show',timerEnabled);timerControls.classList.toggle('show',timerEnabled);
    if(!timerEnabled&&timerRunning){ timerRunning=false;clearInterval(timerInterval); }
});
tmStart.addEventListener('click',()=>{
    if(!timerRunning){
        const min=parseInt(document.getElementById('tmMinInput').value)||0,sec=parseInt(document.getElementById('tmSecInput').value)||0;
        if(timerRemaining===0)timerRemaining=min*60+sec;
        if(timerRemaining>0){ timerRunning=true;timerInterval=setInterval(()=>{timerRemaining--;if(timerRemaining<=0){timerRemaining=0;timerRunning=false;clearInterval(timerInterval);}updateTimer();},1000); }
    }
});
tmPause.addEventListener('click',()=>{ if(timerRunning){ timerRunning=false;clearInterval(timerInterval); } });
tmReset.addEventListener('click',()=>{ timerRunning=false;clearInterval(timerInterval);timerRemaining=0;updateTimer(); });
function updateTimer(){
    const m=Math.floor(timerRemaining/60),s=timerRemaining%60;
    document.getElementById('tmMin').textContent=String(m).padStart(2,'0');
    document.getElementById('tmSec').textContent=String(s).padStart(2,'0');
}

timezoneSelect.addEventListener('change',(e)=>{ selectedTimezone=e.target.value;updateClock(); });

colorSelect.addEventListener('change',(e)=>{
    accentColor=e.target.value;
    const colorMap={black:'#111',red:'#c0392b',blue:'#2980b9',green:'#27ae60',orange:'#e67e22',purple:'#8e44ad'};
    const c=colorMap[accentColor];
    document.querySelectorAll('.time-section,.date-section').forEach(el=>el.style.color=c);
    document.querySelectorAll('.menu-btn span').forEach(el=>el.style.backgroundColor=c);
    document.querySelectorAll('.toggle-track.on').forEach(el=>el.style.backgroundColor=c);
    document.querySelectorAll('.lang-btn.active').forEach(el=>{el.style.backgroundColor=c;el.style.borderColor=c;});
    document.querySelectorAll('.sw-btn').forEach(el=>{el.style.borderColor=c;el.style.color=c;});
});

fsToggle.addEventListener('click',()=>{
    fsEnabled=!fsEnabled;fsTrack.classList.toggle('on',fsEnabled);const t=i18n[currentLang];fsToggle.querySelector('.toggle-label').textContent=fsEnabled?t.fs_on:t.fs_off;
    if(fsEnabled){
        const el=document.documentElement;
        if(el.requestFullscreen){ el.requestFullscreen().catch(()=>{}); }
        else if(el.webkitRequestFullscreen){ el.webkitRequestFullscreen(); }
        else{ alert('您的浏览器不支持全屏模式'); fsEnabled=false; fsTrack.classList.remove('on'); fsToggle.querySelector('.toggle-label').textContent=t.fs_off; }
    } else {
        if(document.fullscreenElement){ document.exitFullscreen().catch(()=>{}); }
        else if(document.webkitFullscreenElement){ document.webkitExitFullscreen(); }
    }
});

// ========== 日期格式 ==========
document.querySelectorAll('.fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.fmt-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        dateFormat = btn.dataset.fmt;
        updateClock();
    });
});

// ========== 字体大小 ==========
sizeSlider.addEventListener('input', (e) => {
    const val = e.target.value;
    document.getElementById('time').style.fontSize = val + 'rem';
    document.getElementById('date').style.fontSize = (val * 0.4) + 'rem';
});

// ========== 主题切换 ==========
document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.theme-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const theme = btn.dataset.theme;
        document.body.classList.remove('dark');
        if (theme === 'dark') document.body.classList.add('dark');
        if (theme === 'oled') { document.body.classList.add('dark'); document.body.style.backgroundColor = '#000'; }
        else { document.body.style.backgroundColor = ''; }
    });
});

// ========== 世界时钟 ==========
function updateWorldClocks() {
    worldClockList.innerHTML = '';
    worldClocks.forEach((tz, idx) => {
        const now = new Date();
        const fmt = new Intl.DateTimeFormat('en-US', {
            timeZone: tz,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: !format24h
        });
        const timeStr = fmt.format(now);
        const city = tz.split('/').pop().replace(/_/g, ' ');
        const div = document.createElement('div');
        div.className = 'world-clock-item';
        div.innerHTML = `<span>${city}</span><span><span class="world-clock-time">${timeStr}</span><span class="world-clock-del" data-idx="${idx}">×</span></span>`;
        worldClockList.appendChild(div);
    });
    document.querySelectorAll('.world-clock-del').forEach(del => {
        del.addEventListener('click', (e) => {
            e.stopPropagation();
            const idx = parseInt(e.target.dataset.idx);
            worldClocks.splice(idx, 1);
            updateWorldClocks();
        });
    });
}
worldClockSelect.addEventListener('change', (e) => {
    const tz = e.target.value;
    if (tz && !worldClocks.includes(tz)) {
        worldClocks.push(tz);
        updateWorldClocks();
    }
    worldClockSelect.value = '';
});

// ========== 点击复制时间 ==========
document.querySelector('.clock-container').addEventListener('click', () => {
    const text = document.getElementById('time').textContent.trim();
    navigator.clipboard.writeText(text).catch(() => {});
});

function generateShareURL() {
    const params = new URLSearchParams();
    params.set('lang', currentLang);
    params.set('theme', document.querySelector('.theme-btn.active')?.dataset.theme || 'light');
    params.set('fmt', dateFormat);
    params.set('size', sizeSlider.value);
    params.set('color', accentColor);
    if (worldClocks.length) params.set('cities', worldClocks.join(','));
    
    const t = {
        ganzhi: ganzhiEnabled ? '1' : '0',
        week: weekEnabled ? '1' : '0',
        julian: julianEnabled ? '1' : '0',
        doy: doyEnabled ? '1' : '0',
        moon: moonEnabled ? '1' : '0',
        sun: sunEnabled ? '1' : '0',
        tz: tzDisplayEnabled ? '1' : '0',
        sec: secondsEnabled ? '1' : '0',
        colon: colonEnabled ? '1' : '0',
        '24h': format24h ? '1' : '0',
        sw: swEnabled ? '1' : '0',
        timer: timerEnabled ? '1' : '0',
        fs: fsEnabled ? '1' : '0'
    };
    Object.entries(t).forEach(([k, v]) => { if (v === '1') params.set(k, v); });
    params.set('tzname', selectedTimezone);
    
    return `${location.origin}${location.pathname}?${params}`;
}

// ========== 二维码 ==========
function generateQR() {
    const qr = document.getElementById('qrcode');
    qr.innerHTML = '';
    const url = window.location.href;
    try {
        new QRCode(qr, {
            text: url,
            width: 100,
            height: 100,
            colorDark: document.body.classList.contains('dark') ? '#ffffff' : '#000000',
            colorLight: document.body.classList.contains('dark') ? '#000000' : '#ffffff',
            correctLevel: QRCode.CorrectLevel.M
        });
    } catch(e) {
        qr.innerHTML = `<img src="https://api.qrserver.com/v1/create-qr-code/?size=100x100&data=${encodeURIComponent(url)}" style="width:100px;height:100px;">`;
    }
}
document.getElementById('copyShareBtn').addEventListener('click', () => {
    const url = generateShareURL();
    navigator.clipboard.writeText(url).catch(() => {});
});

// ========== 时区处理（优化版）==========

const timezoneCoords = {
    'UTC': { lat: 51.5, lon: 0 },
    'America/New_York': { lat: 40.7, lon: -74.0 },
    'America/Los_Angeles': { lat: 34.1, lon: -118.2 },
    'Europe/London': { lat: 51.5, lon: -0.1 },
    'Europe/Paris': { lat: 48.9, lon: 2.3 },
    'Europe/Berlin': { lat: 52.5, lon: 13.4 },
    'Asia/Tokyo': { lat: 35.7, lon: 139.7 },
    'Asia/Shanghai': { lat: 31.2, lon: 121.5 },
    'Asia/Seoul': { lat: 37.6, lon: 127.0 },
    'Asia/Dubai': { lat: 25.2, lon: 55.3 },
    'Australia/Sydney': { lat: -33.9, lon: 151.2 },
    'Pacific/Auckland': { lat: -36.8, lon: 174.7 }
};

function getTimeInTimezone(date, timezone) {
    if (timezone === 'local') {
        return date;
    }
    const fmt = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        year: 'numeric',
        month: 'numeric',
        day: 'numeric',
        hour: 'numeric',
        minute: 'numeric',
        second: 'numeric',
        hour12: false
    });
    const parts = fmt.formatToParts(date);
    const get = (t) => parseInt(parts.find(p => p.type === t).value, 10);
    const year = get('year');
    const month = get('month') - 1;
    const day = get('day');
    const hour = get('hour');
    const minute = get('minute');
    const second = get('second');
    return {
        _year: year,
        _month: month,
        _day: day,
        _hour: hour,
        _minute: minute,
        _second: second,
        _timezone: timezone,
        getFullYear() { return this._year; },
        getMonth() { return this._month; },
        getDate() { return this._day; },
        getDay() {
            const y = this._year, m = this._month + 1, d = this._day;
            const q = d;
            const mm = m < 3 ? m + 12 : m;
            const yy = m < 3 ? y - 1 : y;
            const k = yy % 100;
            const j = Math.floor(yy / 100);
            const h = (q + Math.floor(13 * (mm + 1) / 5) + k + Math.floor(k / 4) + Math.floor(j / 4) + 5 * j) % 7;
            return ((h + 5) % 7);
        },
        getHours() { return this._hour; },
        getMinutes() { return this._minute; },
        getSeconds() { return this._second; },
        getTime() { return date.getTime(); },
        valueOf() { return date.getTime(); }
    };
}

function getTimezoneAbbr(timezone) {
    if (timezone === 'local') {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    }
    if (timezone === 'UTC') {
        return 'UTC';
    }
    try {
        const now = new Date();
        const s = now.toLocaleTimeString('en-US', {
            timeZone: timezone,
            timeZoneName: 'short'
        });
        const parts = s.split(' ');
        const abbr = parts[parts.length - 1];
        if (abbr.startsWith('GMT')) {
            const longS = now.toLocaleTimeString('en-US', {
                timeZone: timezone,
                timeZoneName: 'long'
            });
            const longParts = longS.split(' ');
            return longParts.slice(-2).join(' ');
        }
        return abbr;
    } catch (e) {
        return timezone.split('/').pop().replace(/_/g, ' ');
    }
}

function getCoordsForTimezone(timezone) {
    if (timezone === 'local') {
        const localTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        return timezoneCoords[localTz] || { lat: 39.9, lon: 116.4 };
    }
    return timezoneCoords[timezone] || { lat: 39.9, lon: 116.4 };
}

function updateClock() {
    const now = new Date();
    const displayTime = getTimeInTimezone(now, selectedTimezone);
    const t = i18n[currentLang];

    const year = displayTime.getFullYear();
    const month = t.months[displayTime.getMonth()];
    const date = String(displayTime.getDate()).padStart(2, '0');
    const day = t.days[displayTime.getDay()];

    let hours = displayTime.getHours();
    const minutes = String(displayTime.getMinutes()).padStart(2, '0');
    const seconds = String(displayTime.getSeconds()).padStart(2, '0');
    let ampm = '';

    if (!format24h) {
        ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12 || 12;
    }
    const hStr = String(hours).padStart(2, '0');

    let dateStr;
    if (dateFormat === 'ymd') {
        dateStr = `${year} ${month} ${date} ${day}`;
    } else if (dateFormat === 'mdy') {
        dateStr = `${month} ${date}, ${year} ${day}`;
    } else if (dateFormat === 'dmy') {
        dateStr = `${date}.${month}.${year} ${day}`;
    } else if (dateFormat === 'iso') {
        dateStr = `${year}-${String(displayTime.getMonth()+1).padStart(2,'0')}-${date} ${day}`;
    }
    document.getElementById('date').textContent = dateStr;

    let timeHTML;
    const sep = colonEnabled ? `<span class="colon">:</span>` : ':';
    if (secondsEnabled) {
        timeHTML = `${hStr}${sep}${minutes}${sep}${seconds}${ampm ? ' ' + ampm : ''}`;
    } else {
        timeHTML = `${hStr}${sep}${minutes}${ampm ? ' ' + ampm : ''}`;
    }
    document.getElementById('time').innerHTML = timeHTML;
    document.getElementById('label').textContent = t.label;

    if (ganzhiEnabled) {
        const gYear = getGanzhiYear(year);
        const gMonth = getGanzhiMonth(year, displayTime.getMonth() + 1);
        const gDay = getGanzhiDay(displayTime);
        const gHour = getGanzhiHour(displayTime.getHours());
        const zodiac = getZodiac(year);
        ganzhiDisplay.textContent = currentLang === 'zh'
            ? `${gYear}年 ${gMonth}月 ${gDay}日 ${gHour}时 · ${zodiac}年`
            : `${gYear} Year ${gMonth} Month ${gDay} Day ${gHour} Hour · ${zodiac} Year`;
    }

    if (weekEnabled) {
        const wn = getWeekNumber(displayTime);
        weekDisplay.textContent = currentLang === 'zh' ? `第 ${wn} 周`
            : currentLang === 'ja' ? `第 ${wn} 週`
            : currentLang === 'ko' ? `제 ${wn} 주`
            : `WEEK ${wn}`;
    }

    if (julianEnabled) {
        julianDisplay.textContent = `JD ${getJulianDay(displayTime)}`;
    }

    if (doyEnabled) {
        const doy = getDayOfYear(displayTime);
        doyDisplay.textContent = currentLang === 'zh' ? `第 ${doy} 天`
            : currentLang === 'ja' ? `${doy} 日目`
            : currentLang === 'ko' ? `${doy} 일째`
            : `DAY ${doy}`;
    }

    if (moonEnabled) {
        const mp = getMoonPhase(displayTime);
        moonDisplay.textContent = currentLang === 'zh' ? moonPhasesZh[mp] : moonPhases[mp];
    }

    if (sunEnabled) {
        const coords = getCoordsForTimezone(selectedTimezone);
        const sun = getSunriseSunset(coords.lat, coords.lon, now);
        sunDisplay.textContent = currentLang === 'zh'
            ? `日出 ${sun.rise} · 日落 ${sun.set}`
            : `RISE ${sun.rise} · SET ${sun.set}`;
    }

    if (tzDisplayEnabled) {
        const tzName = selectedTimezone === 'local'
            ? 'Local'
            : selectedTimezone.split('/').pop().replace(/_/g, ' ');
        tzDisplayEl.textContent = `${tzName} · ${getTimezoneAbbr(selectedTimezone)}`;
    }
}

updateI18n();
updateClock();
generateQR();
setInterval(updateClock, 1000);
setInterval(updateWorldClocks, 1000);

// ========== URL 参数解析 ==========
function parseURLParams() {
    const params = new URLSearchParams(location.search);
    if (!params.has('lang')) return;

    const urlSettings = {
        lang: params.get('lang'),
        theme: params.get('theme'),
        dateFormat: params.get('fmt'),
        fontSize: params.get('size'),
        accentColor: params.get('color'),
        worldClocks: params.get('cities')?.split(',') || [],
        toggles: {
            ganzhi: params.get('ganzhi') === '1',
            week: params.get('week') === '1',
            julian: params.get('julian') === '1',
            doy: params.get('doy') === '1',
            moon: params.get('moon') === '1',
            sun: params.get('sun') === '1',
            tzDisplay: params.get('tz') === '1',
            seconds: params.get('sec') !== '0',
            colon: params.get('colon') !== '0',
            format24h: params.get('24h') !== '0',
            sw: params.get('sw') === '1',
            timer: params.get('timer') === '1',
            fs: params.get('fs') === '1'
        },
        timezone: params.get('tzname') || 'local'
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(urlSettings));
    history.replaceState({}, '', location.pathname);
}

parseURLParams();

// ========== 本地存储持久化 ==========
const STORAGE_KEY = 'timedisplay_settings';

function saveSettings() {
    const settings = {
        lang: currentLang,
        theme: document.querySelector('.theme-btn.active')?.dataset.theme || 'light',
        dateFormat: dateFormat,
        fontSize: sizeSlider.value,
        accentColor: accentColor,
        worldClocks: worldClocks,
        toggles: {
            ganzhi: ganzhiEnabled,
            week: weekEnabled,
            julian: julianEnabled,
            doy: doyEnabled,
            moon: moonEnabled,
            sun: sunEnabled,
            tzDisplay: tzDisplayEnabled,
            seconds: secondsEnabled,
            colon: colonEnabled,
            format24h: format24h,
            sw: swEnabled,
            timer: timerEnabled,
            fs: fsEnabled
        },
        timezone: selectedTimezone
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

function loadSettings() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return;
        const s = JSON.parse(raw);

        // 语言
        if (s.lang) {
            currentLang = s.lang;
            document.querySelectorAll('.lang-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.lang === s.lang);
            });
        }

        // 主题
        if (s.theme) {
            document.querySelectorAll('.theme-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.theme === s.theme);
            });
            document.body.classList.remove('dark');
            if (s.theme === 'dark') document.body.classList.add('dark');
            if (s.theme === 'oled') {
                document.body.classList.add('dark');
                document.body.style.backgroundColor = '#000';
            }
        }

        // 日期格式
        if (s.dateFormat) {
            dateFormat = s.dateFormat;
            document.querySelectorAll('.fmt-btn').forEach(b => {
                b.classList.toggle('active', b.dataset.fmt === s.dateFormat);
            });
        }

        // 字体大小
        if (s.fontSize) {
            sizeSlider.value = s.fontSize;
            document.getElementById('time').style.fontSize = s.fontSize + 'rem';
            document.getElementById('date').style.fontSize = (s.fontSize * 0.4) + 'rem';
        }

        // 强调色
        if (s.accentColor) {
            accentColor = s.accentColor;
            colorSelect.value = s.accentColor;
            const colorMap = {black:'#111',red:'#c0392b',blue:'#2980b9',green:'#27ae60',orange:'#e67e22',purple:'#8e44ad'};
            const c = colorMap[s.accentColor];
            document.querySelectorAll('.time-section,.date-section').forEach(el => el.style.color = c);
            document.querySelectorAll('.menu-btn span').forEach(el => el.style.backgroundColor = c);
            document.querySelectorAll('.toggle-track.on').forEach(el => el.style.backgroundColor = c);
            document.querySelectorAll('.lang-btn.active').forEach(el => { el.style.backgroundColor = c; el.style.borderColor = c; });
            document.querySelectorAll('.sw-btn').forEach(el => { el.style.borderColor = c; el.style.color = c; });
        }

        // 世界时钟
        if (s.worldClocks) {
            worldClocks = s.worldClocks;
            updateWorldClocks();
        }

        // 开关状态
        if (s.toggles) {
            const t = s.toggles;
            ganzhiEnabled = t.ganzhi; ganzhiTrack.classList.toggle('on', t.ganzhi); ganzhiDisplay.classList.toggle('show', t.ganzhi);
            weekEnabled = t.week; weekTrack.classList.toggle('on', t.week); weekDisplay.classList.toggle('show', t.week);
            julianEnabled = t.julian; julianTrack.classList.toggle('on', t.julian); julianDisplay.classList.toggle('show', t.julian);
            doyEnabled = t.doy; doyTrack.classList.toggle('on', t.doy); doyDisplay.classList.toggle('show', t.doy);
            moonEnabled = t.moon; moonTrack.classList.toggle('on', t.moon); moonDisplay.classList.toggle('show', t.moon);
            sunEnabled = t.sun; sunTrack.classList.toggle('on', t.sun); sunDisplay.classList.toggle('show', t.sun);
            tzDisplayEnabled = t.tzDisplay; tzTrack.classList.toggle('on', t.tzDisplay); tzDisplayEl.classList.toggle('show', t.tzDisplay);
            secondsEnabled = t.seconds; secondsTrack.classList.toggle('on', t.seconds);
            colonEnabled = t.colon; colonTrack.classList.toggle('on', t.colon);
            format24h = t.format24h; formatTrack.classList.toggle('on', t.format24h);
            swEnabled = t.sw; swTrack.classList.toggle('on', t.sw); swDisplay.classList.toggle('show', t.sw); swControls.classList.toggle('show', t.sw);
            timerEnabled = t.timer; timerTrack.classList.toggle('on', t.timer); timerDisplay.classList.toggle('show', t.timer); timerControls.classList.toggle('show', t.timer);
            fsEnabled = t.fs; fsTrack.classList.toggle('on', t.fs);
        }

        // 时区
        if (s.timezone) {
            selectedTimezone = s.timezone;
            timezoneSelect.value = s.timezone;
        }

        updateI18n();
        updateClock();
    } catch (e) {
        console.log('Load settings failed:', e);
    }
}

// 绑定保存事件
[
    ganzhiToggle, weekToggle, julianToggle, doyToggle, moonToggle,
    sunToggle, tzToggle, secondsToggle, colonToggle, formatToggle,
    swToggle, timerToggle, fsToggle
].forEach(el => el.addEventListener('click', saveSettings));

timezoneSelect.addEventListener('change', saveSettings);
colorSelect.addEventListener('change', saveSettings);
sizeSlider.addEventListener('change', saveSettings);
worldClockSelect.addEventListener('change', saveSettings);

document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', saveSettings);
});
document.querySelectorAll('.fmt-btn').forEach(btn => {
    btn.addEventListener('click', saveSettings);
});
document.querySelectorAll('.theme-btn').forEach(btn => {
    btn.addEventListener('click', saveSettings);
});

// 启动时加载
loadSettings();
// ========== 时间戳转换 ==========
const tsInput = document.getElementById('tsInput');
const tsResult = document.getElementById('tsResult');
    let tsDebounce;
tsInput.addEventListener('input', () => {
    clearTimeout(tsDebounce);
    tsDebounce = setTimeout(() => {
        const val = tsInput.value.trim();
        if (!val) { tsResult.textContent = ''; return; }

        let date;
        if (/^\d+$/.test(val)) {
            const num = parseInt(val, 10);
            date = new Date(num > 1e10 ? num : num * 1000);
        } else {
            date = new Date(val);
        }

        if (isNaN(date.getTime())) {
            tsResult.textContent = 'Invalid';
            return;
        }

        const unixSec = Math.floor(date.getTime() / 1000);
        const unixMs = date.getTime();
        const iso = date.toISOString();
        const local = date.toLocaleString(currentLang === 'zh' ? 'zh-CN' : 'en-US');

        tsResult.innerHTML = `
            <div>Unix(s): ${unixSec}</div>
            <div>Unix(ms): ${unixMs}</div>
            <div>ISO: ${iso}</div>
            <div>Local: ${local}</div>
        `;
    }, 300); // 300ms 防抖
});

tsInput.addEventListener('input', () => {
    const val = tsInput.value.trim();
    if (!val) { tsResult.textContent = ''; return; }

    let date;
    // 纯数字 = Unix 时间戳（秒或毫秒）
    if (/^\d+$/.test(val)) {
        const num = parseInt(val, 10);
        date = new Date(num > 1e10 ? num : num * 1000);
    } else {
        date = new Date(val);
    }

    if (isNaN(date.getTime())) {
        tsResult.textContent = 'Invalid';
        return;
    }

    const unixSec = Math.floor(date.getTime() / 1000);
    const unixMs = date.getTime();
    const iso = date.toISOString();
    const local = date.toLocaleString(currentLang === 'zh' ? 'zh-CN' : 'en-US');

    tsResult.innerHTML = `
        <div>Unix(s): ${unixSec}</div>
        <div>Unix(ms): ${unixMs}</div>
        <div>ISO: ${iso}</div>
        <div>Local: ${local}</div>
    `;
});


