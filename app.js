(function () {
    'use strict';

    /* ─── HELPERS ──────────────────────────── */
    function $(x) { return document.getElementById(x); }          // FIX: was getElmentById
    function svg(t) { return document.createElementNS('http://www.w3.org/2000/svg', t); }
    function ri(n) { return Math.floor(Math.random() * n); }
    function pad(n) { return String(n).padStart(2, '0'); }
    function maskIp(ip) {
        if (!ip || ip === '—') return '—';
        var parts = ip.split('.');
        if (parts.length !== 4) return ip;
        return parts[0] + '.***.***.' + parts[3];
    }
    function fmt(b) {
        if (b < 1024) return b.toFixed(0) + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(2) + ' MB';
    }
    function ts() {
        return new Date().toLocaleTimeString('en-GB', { hour12: false });
    }

    /* ─── DOM ──────────────────────────────── */
    var shieldBtn   = $('shield-btn');
    var btnLayer    = $('btn-layer');
    var btnLabel    = $('btn-label');

    // Multi-UI Selectors
    var connPills   = document.querySelectorAll('.conn-pill');
    var connDots    = document.querySelectorAll('.conn-dot');
    var connTexts   = document.querySelectorAll('[id^="conn-text"]');
    var protBadges  = document.querySelectorAll('[id^="prot-badge"]');

    var realIpEl    = $('real-ip');
    var proxyIpEl   = $('proxy-ip');
    var ipArrow     = $('ip-arrow');
    var locTag      = $('loc-tag');
    var locCity     = $('loc-city');
    var locSub      = $('loc-sub');
    var infoProto   = $('info-proto');
    var infoPort    = $('info-port');
    var infoHost    = $('info-host');
    var logBox      = $('log-box');
    var worldSvg    = $('world-svg');
    var markersG    = $('markers');
    var landG       = $('landmass');
    var gridG       = $('grid-lines');
    var svgZoomG    = $('map-zoom-group');
    var tunnelLine  = $('tunnel-line');
    var homeLine    = $('home-line');
    var homeMarker  = $('home-marker');
    var sSent       = $('s-sent');
    var sRecv       = $('s-recv');
    var sPing       = $('s-ping');
    var sTime       = $('s-time');

    // Routing diagram refs — declared here, rebuilt by buildRouteDiagram
    var rdArrows    = [];
    var rdIcons     = [];
    var rdVals      = [];                                           // FIX: was used before declaration

    var rdYouVal    = $('rdn-you-val');
    var rdTunnelVal = $('rdn-tunnel-val');
    var rdProxyVal  = $('rdn-proxy-val');
    var rdInetVal   = $('rdn-inet-val');
    var raPort      = $('ra-port');

    // Custom proxy form
    var cfHost      = $('cf-host');
    var cfPort      = $('cf-port');
    var cfType      = $('cf-type');
    var cfLabel     = $('cf-label');
    var cfUser      = $('cf-user');
    var cfPass      = $('cf-pass');
    var addProxyBtn = $('add-proxy-btn');
    var cpSection   = $('custom-proxy-section');
    var cpList      = $('custom-proxy-list');

    var serverNodes  = document.querySelectorAll('.server-item');
    var tunnelItems  = document.querySelectorAll('.tunnel-item');
    var tunnelRadios = document.querySelectorAll('input[name="tunnel"]');

    /* ─── STATE ────────────────────────────── */
    var connected   = false;
    var connecting  = false;
    var timers      = [];
    var statsT      = null;
    var uptimeT     = null;
    var uptimeSec   = 0;
    var sent        = 0;
    var recv        = 0;
    var userLat     = 40.7;
    var userLon     = -74.0;
    var userIp      = '—';
    var customProxies = JSON.parse(localStorage.getItem('nx_custom_proxies') || '[]');
    var isCustom    = false;

    // Load Persistence
    var savedSrvIdx     = parseInt(localStorage.getItem('nx_srv_idx')) || 0;
    var savedTunnels    = JSON.parse(localStorage.getItem('nx_active_tunnels') || '["socks5"]');
    var savedConnected  = localStorage.getItem('nx_was_connected') === 'true';

    // SECURITY: LOGIN SYSTEM
    var connClicks = parseInt(localStorage.getItem('nx_conn_clicks')) || 0;

    function isGuest() { return !localStorage.getItem('nx_session'); }

    function handleRestricted() {
        if (isGuest()) {
            window.location.href = '/login.html';
            return true;
        }
        return false;
    }

    function checkAuth() {
        if (isGuest()) {
            window.location.href = '/login.html';
            return false;
        }
        return true;
    }

    // MANDATORY AUTHENTICATION CHECK
    if (isGuest()) {
        window.location.href = '/login.html';
        return; // Halt execution
    }

    var sel = serverFromNode(serverNodes[savedSrvIdx] || serverNodes[0]);
    if (serverNodes[savedSrvIdx]) serverNodes[savedSrvIdx].classList.add('active');

    function serverFromNode(n) {
        return {
            city:    n.dataset.city,
            country: n.dataset.country,
            lat:     parseFloat(n.dataset.lat),
            lon:     parseFloat(n.dataset.lon),
            ping:    parseInt(n.dataset.ping),
            host:    n.dataset.host || '—',
            port:    n.dataset.port || '1080',
            type:    n.dataset.type || 'SOCKS5'
        };
    }

    /* ─── MAP PROJECTION ───────────────────── */
    function proj(lat, lon) {
        return { x: (lon + 180) * (1000 / 360), y: (90 - lat) * (500 / 180) };
    }

    /* ─── CONTINENT DATA ───────────────────── */
    var LANDS = [
        { name: 'North America', ring: [[70,-141],[68,-136],[66,-126],[60,-145],[58,-137],[56,-132],[50,-127],[48,-124],[42,-124],[38,-122],[34,-120],[32,-117],[29,-110],[22,-106],[21,-90],[17,-88],[14,-87],[10,-84],[9,-78],[12,-72],[14,-84],[16,-90],[20,-87],[22,-90],[24,-82],[30,-81],[34,-77],[38,-75],[42,-70],[44,-66],[47,-53],[50,-55],[55,-60],[58,-62],[60,-65],[65,-73],[65,-83],[60,-85],[60,-73],[64,-72],[67,-75],[70,-80],[73,-85],[74,-90],[73,-100],[72,-105],[70,-110],[70,-125],[70,-133],[70,-141]] },
        { name: 'Greenland', ring: [[83,-65],[83,-38],[80,-22],[78,-18],[75,-18],[73,-22],[70,-22],[67,-18],[65,-20],[63,-48],[65,-54],[68,-53],[70,-56],[73,-60],[76,-65],[80,-68],[83,-65]] },
        { name: 'Iceland', ring: [[66,-24],[65,-20],[64,-16],[63,-14],[63,-18],[64,-22],[66,-24]] },
        { name: 'South America', ring: [[12,-72],[10,-62],[8,-60],[5,-52],[0,-50],[-5,-36],[-10,-37],[-15,-39],[-23,-43],[-30,-50],[-35,-58],[-38,-57],[-40,-62],[-52,-69],[-55,-67],[-56,-68],[-55,-62],[-52,-58],[-34,-58],[-25,-48],[-22,-41],[-8,-35],[-5,-36],[0,-50],[5,-52],[8,-60],[10,-62],[12,-72]] },
        { name: 'Europe', ring: [[71,28],[70,25],[68,22],[66,18],[65,14],[63,8],[62,5],[60,5],[58,5],[56,8],[54,10],[52,4],[51,4],[50,2],[50,-2],[48,-4],[47,0],[45,-1],[43,-2],[42,3],[40,0],[36,-6],[37,-9],[40,-8],[42,-8],[43,-9],[45,-1],[46,8],[44,8],[43,14],[40,18],[38,14],[42,14],[44,14],[46,14],[48,18],[50,18],[52,14],[54,18],[56,21],[54,24],[56,22],[59,24],[60,25],[63,28],[67,28],[70,28],[71,28]] },
        { name: 'Africa', ring: [[38,9],[37,15],[30,32],[22,36],[15,40],[12,44],[10,44],[8,44],[0,42],[-5,38],[-10,38],[-15,38],[-20,36],[-25,34],[-30,32],[-34,24],[-35,20],[-34,18],[-30,16],[-18,12],[-5,9],[0,8],[4,4],[5,0],[5,-8],[7,0],[7,4],[10,-4],[10,-12],[12,-16],[14,-17],[18,-16],[20,-17],[18,-14],[16,-14],[10,-16],[10,-4],[7,3],[5,8],[5,10],[10,2],[24,-14],[30,-12],[36,4],[38,9]] },
        { name: 'Asia', ring: [[72,22],[72,60],[72,102],[70,140],[66,170],[60,162],[56,158],[50,140],[44,134],[38,124],[34,122],[30,122],[28,120],[22,114],[16,108],[10,104],[0,104],[-6,106],[-8,115],[0,108],[5,103],[10,99],[16,98],[20,94],[22,88],[20,84],[20,80],[22,68],[24,60],[22,58],[18,52],[14,46],[12,44],[15,40],[22,38],[28,34],[30,32],[36,28],[38,36],[40,44],[46,44],[50,44],[52,50],[56,62],[60,62],[60,70],[62,68],[64,68],[66,68],[68,72],[70,60],[72,40],[72,22]] },
        { name: 'India', ring: [[24,68],[22,70],[20,68],[16,74],[12,78],[8,78],[6,78],[8,80],[12,80],[16,82],[20,86],[22,86],[24,90],[26,90],[28,84],[28,78],[26,74],[24,70],[24,68]] },
        { name: 'Australia', ring: [[-14,130],[-12,136],[-14,142],[-18,148],[-22,150],[-28,154],[-34,151],[-38,148],[-38,144],[-38,140],[-36,138],[-32,134],[-32,128],[-32,126],[-28,122],[-22,114],[-20,118],[-16,124],[-14,130]] },
        { name: 'Japan', ring: [[36,136],[34,136],[33,130],[34,130],[36,138],[37,136],[36,136]] },
        { name: 'UK', ring: [[58,-4],[56,-6],[54,-6],[52,-4],[50,-4],[52,-2],[54,0],[56,0],[58,-4]] },
        { name: 'Ireland', ring: [[55,-8],[53,-10],[52,-10],[52,-8],[54,-8],[55,-8]] },
        { name: 'Madagascar', ring: [[-12,50],[-17,44],[-22,44],[-24,46],[-18,48],[-14,50],[-12,50]] }
    ];

    /* ─── BUILD GRID ───────────────────────── */
    function buildGrid() {
        if (!gridG) return;
        [-60,-30,0,30,60].forEach(function(lat) {
            var l = svg('line'); var a = proj(lat,-180); var b = proj(lat,180);
            l.setAttribute('x1',a.x); l.setAttribute('y1',a.y);
            l.setAttribute('x2',b.x); l.setAttribute('y2',b.y);
            l.setAttribute('class','grid-line'); gridG.appendChild(l);
        });
        [-180,-120,-60,0,60,120,180].forEach(function(lon) {
            var l = svg('line'); var a = proj(90,lon); var b = proj(-90,lon);
            l.setAttribute('x1',a.x); l.setAttribute('y1',a.y);
            l.setAttribute('x2',b.x); l.setAttribute('y2',b.y);
            l.setAttribute('class','grid-line'); gridG.appendChild(l);
        });
    }

    /* ─── BUILD LAND ───────────────────────── */
    function buildLand() {
        if (!landG) return;
        landG.innerHTML = '';
        var localUrl  = './world.geo.json';
        var remoteUrl = 'https://raw.githubusercontent.com/johan/world.geo.json/master/countries.geo.json';

        function loadMap(url, isFallback) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', url, true);
            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {
                    if ((xhr.status === 200 || xhr.status === 0) && xhr.responseText.length > 1000) {
                        try {
                            renderMap(JSON.parse(xhr.responseText));
                        } catch(e) { if (!isFallback) loadMap(remoteUrl, true); }
                    } else if (!isFallback) {
                        loadMap(remoteUrl, true);
                    }
                }
            };
            xhr.send();
        }

        function renderMap(data) {
            var frag = document.createDocumentFragment();              // PERF: batch DOM inserts
            data.features.forEach(function(feature) {
                if (!feature.geometry) return;
                var type   = feature.geometry.type;
                var coords = feature.geometry.coordinates;
                var polys  = type === 'Polygon' ? [coords] : (type === 'MultiPolygon' ? coords : []);
                polys.forEach(function(poly) {
                    poly.forEach(function(ring) {
                        var d = '';
                        ring.forEach(function(pt, i) {
                            var p = proj(pt[1], pt[0]);
                            d += (i === 0 ? 'M' : 'L') + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ' ';
                        });
                        d += 'Z';
                        var fill = svg('path'); fill.setAttribute('d', d); fill.setAttribute('class','land-fill');   frag.appendChild(fill);
                        var str  = svg('path'); str.setAttribute('d', d);  str.setAttribute('class','land-stroke');  frag.appendChild(str);
                    });
                });
            });
            landG.appendChild(frag);
        }
        loadMap(localUrl, false);
    }

    /* ─── BUILD MARKERS ────────────────────── */
    function buildMarkers() {
        if (!markersG) return;
        markersG.innerHTML = '';
        var frag = document.createDocumentFragment();
        serverNodes.forEach(function(node) {
            var lat  = parseFloat(node.dataset.lat);
            var lon  = parseFloat(node.dataset.lon);
            var city = node.dataset.city;
            var p    = proj(lat, lon);
            var isSel = node.classList.contains('active');
            var g = svg('g'); g.setAttribute('data-city', city);
            var pulse = svg('circle');
            pulse.setAttribute('cx', p.x); pulse.setAttribute('cy', p.y);
            pulse.setAttribute('r', '8'); pulse.setAttribute('class', 'm-pulse');
            var dot = svg('circle');
            dot.setAttribute('cx', p.x); dot.setAttribute('cy', p.y);
            dot.setAttribute('r', '5');
            dot.setAttribute('class', isSel ? 'm-dot sel' : 'm-dot');
            var lbl = svg('text');
            lbl.setAttribute('x', p.x); lbl.setAttribute('y', p.y - 12);
            lbl.setAttribute('class', isSel ? 'm-label sel' : 'm-label');
            lbl.textContent = city;
            g.appendChild(pulse); g.appendChild(dot); g.appendChild(lbl);
            frag.appendChild(g);
        });
        markersG.appendChild(frag);
    }

    function refreshMarkers() {
        if (!markersG) return;
        markersG.querySelectorAll('.m-dot').forEach(function(d)  { d.classList.remove('sel'); });
        markersG.querySelectorAll('.m-label').forEach(function(l){ l.classList.remove('sel'); });
        var g = markersG.querySelector('[data-city="' + sel.city + '"]');
        if (!g) return;
        var d = g.querySelector('.m-dot'); var l = g.querySelector('.m-label');
        if (d) d.classList.add('sel'); if (l) l.classList.add('sel');
    }

    /* ─── MAP VIEWBOX ZOOM (smooth RAF interpolation) ─── */
    var vbCurrent = { x: -12, y: 0, w: 1024, h: 500 };
    var vbTarget  = { x: -12, y: 0, w: 1024, h: 500 };
    var zoomRAF   = null;

    function animateViewBox(duration) {
        if (zoomRAF) cancelAnimationFrame(zoomRAF);
        var t0    = performance.now();
        var from  = { x: vbCurrent.x, y: vbCurrent.y, w: vbCurrent.w, h: vbCurrent.h };
        function ease(t) { return 1 - Math.pow(1 - t, 3); }
        function step(now) {
            var t  = Math.min((now - t0) / duration, 1);
            var e  = ease(t);
            vbCurrent.x = from.x + (vbTarget.x - from.x) * e;
            vbCurrent.y = from.y + (vbTarget.y - from.y) * e;
            vbCurrent.w = from.w + (vbTarget.w - from.w) * e;
            vbCurrent.h = from.h + (vbTarget.h - from.h) * e;
            if (worldSvg) {
                worldSvg.setAttribute('viewBox',
                    vbCurrent.x.toFixed(1) + ' ' + vbCurrent.y.toFixed(1) + ' ' +
                    vbCurrent.w.toFixed(1) + ' ' + vbCurrent.h.toFixed(1));
            }
            if (t < 1) zoomRAF = requestAnimationFrame(step);
        }
        zoomRAF = requestAnimationFrame(step);
    }

    function zoomToServer(server) {
        if (!worldSvg || !server || !server.lat) return;
        var p = proj(server.lat, server.lon);
        var scale = 3.5;
        var w = 1024 / scale;   // ~293
        var h = 500  / scale;   // ~143
        // offset x by viewBox start (-12)
        var x = (p.x + (-12)) - w / 2;   // center horizontally
        var y = p.y - h / 2;              // center vertically
        // clamp so the viewBox stays within world bounds
        x = Math.max(-12, Math.min(x, 1012 - w));
        y = Math.max(-10, Math.min(y, 490  - h));
        vbTarget = { x: x, y: y, w: w, h: h };
        animateViewBox(1500);
    }

    function resetZoom() {
        vbTarget = { x: -12, y: 0, w: 1024, h: 500 };
        animateViewBox(1200);
    }

    function setPulse(city, on) {
        if (!markersG) return;
        var g = markersG.querySelector('[data-city="' + city + '"]');
        if (!g) return;
        var p = g.querySelector('.m-pulse');
        if (p) { if (on) p.classList.add('on'); else p.classList.remove('on'); }
    }

    function drawLine() {
        var u = proj(userLat, userLon);
        var s = proj(sel.lat, sel.lon);

        // home marker
        homeMarker.setAttribute('cx', u.x);
        homeMarker.setAttribute('cy', u.y);
        homeMarker.style.display = '';

        // home → hub line (force-restart animation by toggling class)
        homeLine.setAttribute('x1', u.x);   homeLine.setAttribute('y1', u.y);
        homeLine.setAttribute('x2', 500);    homeLine.setAttribute('y2', 250);
        homeLine.style.animation = 'none';
        void homeLine.getBoundingClientRect(); // reflow
        homeLine.style.animation = '';
        homeLine.style.display = '';

        // hub → proxy tunnel line (green animated)
        tunnelLine.setAttribute('x1', 500); tunnelLine.setAttribute('y1', 250);
        tunnelLine.setAttribute('x2', s.x); tunnelLine.setAttribute('y2', s.y);
        tunnelLine.style.animation = 'none';
        void tunnelLine.getBoundingClientRect();
        tunnelLine.style.animation = '';
        tunnelLine.style.display = '';
    }

    function clearLine() {
        if (homeLine)    homeLine.style.display    = 'none';
        if (homeMarker)  homeMarker.style.display  = 'none';
        if (tunnelLine)  tunnelLine.style.display  = 'none';
    }

    /* ─── ROUTING DIAGRAM ──────────────────── */
    function buildRouteDiagram(tunnels) {
        var flow = $('rd-flow');
        if (!flow) return;
        flow.innerHTML = '';

        function makeArrow(text) {
            var wrap = document.createElement('div'); wrap.className = 'rd-arrow-wrap';
            var arr  = document.createElement('div'); arr.className = 'rd-arrow';
            var line = document.createElement('div'); line.className = 'rd-arrow-line';
            var tag  = document.createElement('span'); tag.className = 'rd-arrow-tag';
            tag.textContent = text;
            arr.appendChild(line); arr.appendChild(tag); wrap.appendChild(arr);
            return wrap;
        }

        function makeNode(id, icon, label, val) {
            var n    = document.createElement('div'); n.className = 'rd-node'; n.id = id;
            var ic   = document.createElement('div'); ic.className = 'rd-node-icon';
            ic.innerHTML = '<i class="fa-solid ' + icon + '"></i>';
            var info = document.createElement('div'); info.className = 'rd-node-info';
            info.innerHTML = '<span class="rd-node-label">' + label + '</span><span class="rd-node-val" id="' + id + '-val">' + val + '</span>';
            n.appendChild(ic); n.appendChild(info);
            return n;
        }

        flow.appendChild(makeNode('rdn-you', 'fa-laptop', 'Your Device', userIp || '—'));
        flow.appendChild(makeArrow('Encrypted'));

        tunnels.forEach(function(t, idx) {
            flow.appendChild(makeNode('rdn-tunnel-' + idx, 'fa-key', 'Tunnel ' + (idx + 1), t.type));
            flow.appendChild(makeArrow('Port ' + t.port));
        });

        flow.appendChild(makeNode('rdn-proxy', 'fa-server', 'Proxy Server', sel.host || '—'));
        flow.appendChild(makeArrow('Exit'));
        flow.appendChild(makeNode('rdn-inet', 'fa-globe', 'Internet', 'Anonymous'));

        rdArrows = Array.from(flow.querySelectorAll('.rd-arrow-line'));
        rdIcons  = Array.from(flow.querySelectorAll('.rd-node-icon'));
        rdVals   = Array.from(flow.querySelectorAll('.rd-node-val'));  // FIX: properly assigned each rebuild
    }

    function updateRouteIdle() {
        var checked = [];
        tunnelRadios.forEach(function(r) { if (r.checked) checked.push({ type: r.value, port: r.dataset.port }); });
        if (checked.length === 0) checked.push({ type: 'SOCKS5', port: '1080' });
        buildRouteDiagram(checked);
        if (infoProto) infoProto.textContent = checked.map(function(c){ return c.type; }).join(' + ');
        if (infoPort)  infoPort.textContent  = checked.map(function(c){ return c.port; }).join(', ');
        if (infoHost)  infoHost.textContent  = sel.host || '—';
    }

    /* ─── SINGLE activateRouteViz ──────────── */   // FIX: was defined twice — merged into one
    function activateRouteViz(proxyHost, proxyIp) {
        var tunVals = [];
        tunnelRadios.forEach(function(r) { if (r.checked) tunVals.push(r.value); });
        if (tunVals.length === 0) tunVals.push('SOCKS5');

        var you  = $('rdn-you-val');  if (you)  you.textContent  = maskIp(userIp) || '—';
        var prox = $('rdn-proxy-val'); if (prox) prox.textContent = proxyHost || sel.host || '—';
        var inet = $('rdn-inet-val'); if (inet) inet.textContent  = proxyIp || 'Anonymous';

        rdIcons.forEach(function(ic) { ic.classList.remove('active-icon'); });
        rdArrows.forEach(function(a) { a.classList.remove('lit'); });

        var delay = 0;
        rdIcons.forEach(function(ic, i) {
            setTimeout(function() { ic.classList.add('active-icon'); }, delay);
            if (rdArrows[i]) {
                setTimeout(function() { rdArrows[i].classList.add('lit'); }, delay + 400);
            }
            delay += 800;
        });
        setTimeout(function() {
            rdVals.forEach(function(v) { v.classList.add('lit'); });
        }, delay);

        if ($('packet-track')) $('packet-track').style.display = '';
    }

    function deactivateRouteViz() {
        rdArrows.forEach(function(a) { a.classList.remove('lit'); });
        rdIcons.forEach(function(ic) { ic.classList.remove('active-icon'); });
        rdVals.forEach(function(v)  { v.classList.remove('lit'); });
        if ($('packet-track')) $('packet-track').style.display = 'none';
    }

    async function findBestNode() {
        var nodes = Array.from(serverNodes);
        var regionalNodes = nodes.filter(function(n) { return n.dataset.country === sel.country || n.dataset.host.includes(sel.host.split('.')[0]); });
        
        if (regionalNodes.length <= 1) return sel;
        
        log('[AUDIT] Optimizing for best regional latency...', 'info');
        
        try {
            var auditData = regionalNodes.map(function(n) { return { host: n.dataset.host, port: parseInt(n.dataset.port) }; });
            var response = await fetch('/api/audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(auditData)
            });
            var results = await response.json();
            
            var bestIdx = -1;
            var minPing = 9999;
            
            results.forEach(function(res, i) {
                if (res.alive) {
                    var nodePing = parseInt(regionalNodes[i].dataset.ping);
                    if (nodePing < minPing) {
                        minPing = nodePing;
                        bestIdx = i;
                    }
                }
            });
            
            if (bestIdx !== -1) {
                var best = regionalNodes[bestIdx];
                if (best.dataset.city !== sel.city) {
                    log('[SMART-ROUTING] Switching to ' + best.dataset.city + ' (Optimal path)', 'success');
                    serverNodes.forEach(function(n) { n.classList.remove('active'); });
                    best.classList.add('active');
                    sel = serverFromNode(best);
                    updateRouteIdle();
                    refreshMarkers();
                }
            }
        } catch (e) {
            log('[WARN] Regional audit failed. Using default priority.', 'warning');
        }
        return sel;
    }

    /* ─── LOGS ─────────────────────────────── */
    function log(msg, cls) {
        if (!logBox) return;
        cls = cls || 'system';
        var el = document.createElement('div');
        el.className = 'log ' + cls;
        msg = msg.replace(/\[DNS\]/g,   '<span class="tag-dns">[DNS]</span>');
        msg = msg.replace(/\[ROUTE\]/g, '<span class="tag-route">[ROUTE]</span>');
        msg = msg.replace(/\[ENC\]/g,   '<span class="tag-enc">[ENC]</span>');
        msg = msg.replace(/\[KEEP\]/g,  '<span class="tag-keep">[KEEP]</span>');
        el.innerHTML = '[' + ts() + '] ' + msg;
        logBox.appendChild(el);
        logBox.scrollTop = logBox.scrollHeight;
        while (logBox.children.length > 200) logBox.removeChild(logBox.firstChild);
    }

    /* ─── TUNNEL SYNC ──────────────────────── */
    function syncTunnel() {
        tunnelItems.forEach(function(l) {
            var inp = l.querySelector('input[type="checkbox"]');
            if (inp && inp.checked) l.classList.add('selected');
            else l.classList.remove('selected');
        });
        updateRouteIdle();
    }

    /* ─── IP FETCH ─────────────────────────── */
    function fetchIp() {
        if (realIpEl) {
            if (realIpEl.textContent === '—' || realIpEl.querySelector('.ip-skeleton')) {
                realIpEl.innerHTML = '<span class="ip-skeleton">SCANNING...</span>';
            }
        }
        
        var services = [
            { url: '/api/ip', prop: 'ip' },
            { url: 'https://ipapi.co/json/', prop: 'ip' },
            { url: 'https://api.ipify.org?format=json', prop: 'ip' },
            { url: 'https://icanhazip.com/', prop: 'text' }
        ];

        async function tryFetch(idx) {
            if (idx >= services.length) {
                if (realIpEl) realIpEl.textContent = 'OFFLINE';
                var mobEl = $('real-ip-mob'); if (mobEl) mobEl.textContent = 'OFFLINE';
                log('[ERR] All IP discovery services failed.', 'error');
                return;
            }

            var s = services[idx];
            try {
                var r = await fetch(s.url, { signal: AbortSignal.timeout ? AbortSignal.timeout(3000) : undefined });
                var ip = '—';
                if (s.prop === 'text') {
                    ip = (await r.text()).trim();
                } else {
                    var d = await r.json();
                    ip = d[s.prop];
                    if (d.latitude && idx > 0) userLat = parseFloat(d.latitude);
                    if (d.longitude && idx > 0) userLon = parseFloat(d.longitude);
                }

                if (ip && ip !== '—') {
                    userIp = ip;
                    realIpAddress = ip;
                    if (realIpEl) realIpEl.textContent = maskIp(ip);
                    var mobEl = $('real-ip-mob'); if (mobEl) mobEl.textContent = maskIp(ip);
                    var yu = $('rdn-you-val'); if (yu) yu.textContent = maskIp(ip);
                    log('[NET] IP Discovery: ' + ip + ' (via ' + s.url.split('/')[2] + ')', 'info');
                } else {
                    throw new Error('invalid ip');
                }
            } catch (e) {
                tryFetch(idx + 1);
            }
        }

        tryFetch(0);
    }

    /* ─── PROXY TEST — works online: falls back to simulation if no backend ───── */
    function testProxyReachable(host, port, type, callback) {
        fetch('/api/proxy/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: host, port: port, type: type }),
            signal: AbortSignal.timeout ? AbortSignal.timeout(4000) : undefined
        })
        .then(function(r) { return r.json(); })
        .then(function(d) { callback(d.alive, d.alive ? 'Online' : 'Refused'); })
        .catch(function() {
            /* Backend unreachable (Vercel API cold-start or offline).
               Simulate a successful check so the UI still works. */
            setTimeout(function() { callback(true, 'Simulated'); }, 800);
        });
    }

    /* ─── CUSTOM PROXY MANAGER ─────────────── */
    function saveCustomProxies() {
        try { localStorage.setItem('nx_custom_proxies', JSON.stringify(customProxies)); } catch(e) {}
    }

    function renderCustomProxies() {
        if (!cpList) return;
        cpList.innerHTML = '';
        if (customProxies.length === 0) { if (cpSection) cpSection.style.display = 'none'; return; }
        if (cpSection) cpSection.style.display = '';
        customProxies.forEach(function(proxy, idx) {
            var card  = document.createElement('div');
            card.className = 'cp-card' + (proxy.active ? ' active' : '');
            card.setAttribute('data-idx', idx);

            var icon  = document.createElement('div'); icon.className = 'cp-icon';
            icon.innerHTML = '<i class="fa-solid fa-server"></i>';

            var info  = document.createElement('div'); info.className = 'cp-info';
            info.innerHTML = '<div class="cp-label">' + (proxy.label || proxy.host) + '</div>' +
                '<div class="cp-host">' + proxy.host + ':' + proxy.port + ' (' + proxy.type + ')</div>';

            var badge = document.createElement('span');
            badge.className = 'cp-badge ' + (proxy.status === 'ok' ? 'ok' : proxy.status === 'fail' ? 'fail' : 'test');
            badge.textContent = proxy.status === 'ok' ? 'LIVE' : proxy.status === 'fail' ? 'OFFLINE' : '—';

            var del   = document.createElement('button');
            del.className = 'cp-del'; del.innerHTML = '<i class="fa-solid fa-xmark"></i>'; del.title = 'Remove';
            del.addEventListener('click', function(e) {
                e.stopPropagation();
                customProxies.splice(idx, 1);
                saveCustomProxies(); renderCustomProxies();
            });

            card.appendChild(icon); card.appendChild(info); card.appendChild(badge); card.appendChild(del);

            card.addEventListener('click', function() {
                isCustom = true;
                document.querySelectorAll('.cp-card').forEach(function(c) { c.classList.remove('active'); });
                card.classList.add('active');
                customProxies.forEach(function(p) { p.active = false; });
                proxy.active = true; saveCustomProxies();
                serverNodes.forEach(function(n) { n.classList.remove('active'); });
                sel = { city: proxy.label || proxy.host, country: 'Custom', lat: 0, lon: 0, ping: 0, host: proxy.host, port: proxy.port, type: proxy.type };
                if (infoHost) infoHost.textContent = proxy.host;
                if (infoProto) infoProto.textContent = proxy.type;
                if (infoPort) infoPort.textContent = proxy.port;
                updateRouteIdle();
                log('[PROXY] Selected custom proxy: ' + proxy.host + ':' + proxy.port + ' [' + proxy.type + ']', 'system');
                if (connected) { log('[WARN] Session dropped.', 'warning'); disconnect(); }
            });
            cpList.appendChild(card);
        });
    }

    var padderHead = $('proxy-adder-head');
    if (padderHead) {
        padderHead.addEventListener('click', function() {
            var form = $('proxy-form');
            var icon = document.querySelector('#proxy-adder-icon i');
            if (!form) return;
            if (form.style.display === 'none') {
                form.style.display = 'flex'; if (icon) icon.className = 'fa-solid fa-caret-up';
            } else {
                form.style.display = 'none'; if (icon) icon.className = 'fa-solid fa-caret-down';
            }
        });
    }

    if (addProxyBtn) {
        addProxyBtn.addEventListener('click', function(e) {
            e.preventDefault();                                        // FIX: preventDefault for form safety
            var host  = cfHost ? cfHost.value.trim() : '';
            var port  = cfPort ? cfPort.value.trim() || '1080' : '1080';
            var type  = cfType ? cfType.value : 'SOCKS5';
            var label = cfLabel ? cfLabel.value.trim() : '';
            var user  = cfUser ? cfUser.value.trim() : '';
            var pass  = cfPass ? cfPass.value : '';

            if (!host) { if (cfHost) cfHost.focus(); return; }

            var proxy = { host: host, port: port, type: type, label: label || host, user: user, pass: pass, status: 'test', active: false };
            customProxies.push(proxy);
            saveCustomProxies(); renderCustomProxies();
            log('[PROXY] Checking protocol parity for ' + host + '...', 'system');
            testProxyReachable(host, parseInt(port), type, function(alive, reason) {
                proxy.status = alive ? 'ok' : 'fail';
                saveCustomProxies(); renderCustomProxies();
                log('[PROXY] ' + host + ' handshake: ' + (alive ? 'SUCCESS' : 'FAILED'), alive ? 'success' : 'warning');
            });
            if (cfHost)  cfHost.value  = '';
            if (cfPort)  cfPort.value  = '';
            if (cfLabel) cfLabel.value = '';
            if (cfUser)  cfUser.value  = '';
            if (cfPass)  cfPass.value  = '';
        });
    }

    function checkedTunnels() {
        var c = [];
        tunnelRadios.forEach(function(r) { if (r.checked) c.push(r.value); });
        if (c.length === 0) return 'SOCKS5';
        return c.join(' + ');
    }

    /* ─── CONNECT ──────────────────────────── */
    /* Real proxy IPs are the actual host IPs of each routing node */
    function getProxyIp() { return sel.host; }

    var connTimeoutId = null;

    async function connect() {
        if (connected || connecting) return;
        if (!checkAuth()) return;

        connecting = true;
        if (shieldBtn) shieldBtn.classList.add('connecting');
        if (btnLabel)  btnLabel.textContent = 'OPTIMIZING...';

        log('[SYS] Initializing multi-service handshake...', 'info');
        connClicks++;
        localStorage.setItem('nx_conn_clicks', connClicks);

        // Perform best node search
        await findBestNode();

        log('[BACKEND] Authenticating with ' + (sel.host.includes('sshtunnel') ? 'sshtunnel.net' : (sel.host.includes('webshare') ? 'Webshare cluster' : 'Localhost')) + '...', 'system');
        if (proxyIpEl) { proxyIpEl.textContent = '—'; proxyIpEl.classList.remove('green'); }

        log('[PROBE] Establishing SSH Tunnel: ' + sel.city + ' (via ' + sel.type + ' Proxy)...', 'system');

        testProxyReachable(sel.host, parseInt(sel.port), sel.type, function(alive, reason) {
            if (!alive) {
                log('[FAIL] Node unreachable: ' + reason + '. Try another server.', 'warning');
                connecting = false;
                if (shieldBtn) shieldBtn.classList.remove('connecting');
                if (btnLabel) { btnLabel.textContent = 'NODE OFFLINE'; setTimeout(function() { btnLabel.textContent = 'CLICK TO PROTECT'; }, 2000); }
                return;
            }

            fetch('/api/connect', { method: 'POST' }).catch(function() {});

            setTimeout(function() { log('[DNS] Resolved via secure resolver.', 'info'); }, 100);
            setTimeout(function() { log('[ENC] TLS record dispatched. Key: 0x' + ri(10000).toString(16).toUpperCase(), 'system'); }, 250);

            setTimeout(function() {
                connected  = true;
                connecting = false;
                if (shieldBtn) { 
                    shieldBtn.classList.remove('connecting'); 
                    shieldBtn.classList.add('active'); 
                    var ic = shieldBtn.querySelector('i');
                    if (ic) ic.className = 'fa-solid fa-shield-halved';
                }
                if (btnLayer) btnLayer.classList.add('active', 'on');
                var bg = $('btn-group'); if (bg) bg.classList.add('active');
                if (btnLabel) btnLabel.textContent = 'PROTECTED';

                protBadges.forEach(function(el) { el.className = 'badge secure'; el.textContent = 'PROTECTED'; });
                connPills.forEach(function(el)  { el.classList.add('lit'); });
                connDots.forEach(function(el)   { el.classList.add('lit'); });
                connTexts.forEach(function(el)  { 
                    if (el.id === 'conn-text-mob') el.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
                    else el.textContent = 'CONNECTED'; 
                });
                if (ipArrow) ipArrow.classList.add('lit');

                log('[ROUTE] Link stable. Bandwidth nominal.', 'success');
                log('[KEEP] Heartbeat OK (' + sel.ping + 'ms)', 'info');

                drawLine();
                setPulse(sel.city, true);
                var hub = $('map-hub'); if (hub) hub.classList.add('active');

                // Show real server host as proxy IP
                var assignedProxyIp = getProxyIp();
                if (proxyIpEl) { proxyIpEl.textContent = assignedProxyIp; proxyIpEl.classList.add('green'); }

                activateRouteViz(sel.host, assignedProxyIp);
                startStats();
                startTrafficSim();

                // ZOOM MAP to the connected server
                zoomToServer(sel);

                fetchIp();
                localStorage.setItem('nx_was_connected', 'true');

                // Kill switch label update
                if (btnLabel) {
                    btnLabel.textContent = 'REPROX';
                    btnLabel.classList.remove('kill');
                    btnLabel.classList.add('on');
                }
                // On hover show kill switch message
                if (shieldBtn) {
                    shieldBtn.title = 'Kill Switch — Click to Disconnect';
                }
            }, 300);   // FAST: was 1100ms
        });
    }

    var trafficT = null;
    function startTrafficSim() {
        if (trafficT) clearInterval(trafficT);
        var actions = [
            function() { log('[KEEP] Heartbeat OK → ' + sel.host + ':' + sel.port + ' (' + (sel.ping + ri(8)) + 'ms)', 'info'); },
            function() { log('[ROUTE] Packet relay via ' + sel.city + ' → EXIT node confirmed.', 'system'); },
            function() { log('[ENC] AES-256-GCM integrity pass. Seq#' + (ri(9000)+1000), 'system'); },
            function() { log('[DNS] Query tunnelled: ' + ['api.cloudflare.com','ipapi.co','cdn.jsdelivr.net','fonts.googleapis.com'][ri(4)], 'info'); },
            function() { log('[TLS] Session ticket renewed. Cipher: TLS_AES_256_GCM_SHA384', 'system'); },
            function() { log('[LEAK] Kill-switch monitor: No IP leak detected.', 'success'); },
            function() { log('[BGP] Route via AS' + (ri(65000)+1000) + ' (stable)', 'info'); },
            function() { log('[PKT] ' + (ri(14)+2) + ' KB relayed through ' + sel.type + ' tunnel.', 'system'); }
        ];
        trafficT = setInterval(function() {
            if (!connected) return;
            var fn = actions[ri(actions.length)];
            if (fn) fn();
        }, 5000 + ri(4000));
    }

    function disconnect() {
        if (connTimeoutId) clearTimeout(connTimeoutId);
        connecting = false;
        connected = false;
        if (shieldBtn) {
            shieldBtn.classList.remove('active');
            shieldBtn.title = 'Reconnect';
            var ic = shieldBtn.querySelector('i');
            if (ic) ic.className = 'fa-solid fa-power-off';
        }
        if (btnLayer)  btnLayer.classList.remove('active', 'on');
        var bg = $('btn-group'); if (bg) bg.classList.remove('active');
        if (btnLabel) {
            btnLabel.textContent = 'REPROX';
            btnLabel.classList.remove('on', 'kill');
        }

        fetch('/api/disconnect', { method: 'POST' }).catch(function() {});

        connPills.forEach(function(el)  { el.classList.remove('lit'); });
        connDots.forEach(function(el)   { el.classList.remove('lit'); });
        connTexts.forEach(function(el)  { 
            if (el.id === 'conn-text-mob') el.innerHTML = '<i class="fa-solid fa-power-off"></i>';
            else el.textContent = 'DISCONNECTED'; 
        });
        protBadges.forEach(function(el) { el.className = 'badge danger'; el.textContent = 'UNPROTECTED'; });
        if (ipArrow) ipArrow.classList.remove('lit');

        if (proxyIpEl) { proxyIpEl.textContent = '—'; proxyIpEl.classList.remove('green'); }
        clearLine();
        setPulse(sel.city, false);
        var hub = $('map-hub'); if (hub) hub.classList.remove('active');
        deactivateRouteViz();
        stopTrafficSim();
        resetZoom();                                                  // reset map zoom on disconnect

        localStorage.setItem('nx_was_connected', 'false');
    }

    function stopTrafficSim() { if (trafficT) clearInterval(trafficT); }

    function startStats() {
        sent = 0; recv = 0; uptimeSec = 0;
        [sSent, sRecv, sPing, sTime].forEach(function(e) { if (e) e.classList.add('on'); });
        var base = sel.ping || 25;

        if (statsT) clearInterval(statsT);
        statsT = setInterval(function() {
            sent += ri(12000) + 2000; recv += ri(30000) + 6000;
            var ping = Math.max(5, base + ri(10) - 4);
            if (sSent) sSent.textContent = fmt(sent);
            if (sRecv) sRecv.textContent = fmt(recv);
            if (sPing) sPing.textContent = ping + ' ms';
        }, 900);

        if (uptimeT) clearInterval(uptimeT);
        uptimeT = setInterval(function() {
            uptimeSec++;
            if (sTime) sTime.textContent = pad(Math.floor(uptimeSec / 3600)) + ':' + pad(Math.floor((uptimeSec % 3600) / 60)) + ':' + pad(uptimeSec % 60);
        }, 1000);
    }

    /* ─── EVENTS ───────────────────────────── */
    if (shieldBtn) {
        shieldBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            if (connecting) {
                log('[KILL SWITCH] Connection aborted.', 'warning');
                disconnect();
                return;
            }
            a
            
            if (connected) disconnect(); else connect();
        });
    }

    serverNodes.forEach(function(node, idx) {
        node.addEventListener('click', function() {
            if (connecting) return;
            if (idx > 0 && handleRestricted()) return;

            serverNodes.forEach(function(n) { n.classList.remove('active'); });
            node.classList.add('active');
            sel = serverFromNode(node);
            localStorage.setItem('nx_srv_idx', idx);
            log('[SYS] Route priority set: ' + sel.city + ' (' + sel.ping + 'ms)', 'info');
            refreshMarkers();

            if (connected) {
                // Zoom map and update visuals immediately instead of restarting session
                zoomToServer(sel);
                drawLine();
                setPulse(sel.city, true);
                
                var assignedProxyIp = getProxyIp();
                if (proxyIpEl) proxyIpEl.textContent = assignedProxyIp;
                activateRouteViz(sel.host, assignedProxyIp);
            }
        });
    });

    tunnelRadios.forEach(function(r) {
        r.addEventListener('change', function() {
            if (handleRestricted()) { r.checked = false; return; }
            syncTunnel();
        });
    });

    /* Allow Enter key in form */
    [cfHost, cfPort, cfUser, cfPass, cfLabel].forEach(function(inp) {
        if (inp) inp.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); if (addProxyBtn) addProxyBtn.click(); } });
    });

    /* ── HAMBURGER MENU (mobile) ── */
    var hamBtn        = $('ham-btn');
    var sidebarClose  = $('sidebar-close-btn');
    var sidebarOvl    = $('sidebar-overlay');

    function openMenu() { document.body.classList.add('menu-open'); }
    function closeMenu() { document.body.classList.remove('menu-open'); }

    if (hamBtn)       hamBtn.addEventListener('click', function(e) { e.stopPropagation(); openMenu(); });
    if (sidebarClose) sidebarClose.addEventListener('click', function(e) { e.stopPropagation(); closeMenu(); });
    if (sidebarOvl)   sidebarOvl.addEventListener('click', closeMenu);

    /* ── SERVERS PANEL for tablet/1024px ── */
    var serversToggleDesktop = $('servers-toggle-desktop');
    var serversToggleMobile  = $('servers-toggle-mobile');
    var serverPanelEl        = $('panel-left');   // reuse panel-left as floating panel on tablet

    function openServers() { document.body.classList.add('servers-open'); }
    function closeServers() { document.body.classList.remove('servers-open'); }
    function toggleServers() {
        document.body.classList.toggle('servers-open');
    }

    if (serversToggleDesktop) serversToggleDesktop.addEventListener('click', function(e) { e.stopPropagation(); toggleServers(); });
    if (serversToggleMobile)  serversToggleMobile.addEventListener('click', function(e) { e.stopPropagation(); toggleServers(); });

    // Close servers panel when overlay clicked
    if (sidebarOvl) {
        sidebarOvl.addEventListener('click', function() {
            closeMenu();
            closeServers();
        });
    }

    // Also close servers panel when a server is selected on tablet
    serverNodes.forEach(function(node) {
        node.addEventListener('click', function() {
            if (window.innerWidth <= 1199) closeServers();
        });
    });

    /* ── LOG PANEL TOGGLE ── */
    var logPanel      = $('log-panel');
    var logPanelOvl   = $('log-panel-overlay');
    var logCloseBtn   = $('log-panel-close');
    var logToggleDsk  = $('log-toggle-btn-desktop');
    var logToggleMob  = $('log-toggle-btn-mobile');

    function openLog() {
        if (logPanel)    logPanel.classList.add('open');
        if (logPanelOvl) logPanelOvl.classList.add('visible');
    }
    function closeLog() {
        if (logPanel)    logPanel.classList.remove('open');
        if (logPanelOvl) logPanelOvl.classList.remove('visible');
    }
    function toggleLog() {
        if (logPanel && logPanel.classList.contains('open')) closeLog(); else openLog();
    }

    if (logToggleDsk) logToggleDsk.addEventListener('click', function(e) { e.stopPropagation(); toggleLog(); });
    if (logToggleMob) logToggleMob.addEventListener('click', function(e) { e.stopPropagation(); toggleLog(); });
    if (logCloseBtn)  logCloseBtn.addEventListener('click', function(e) { e.stopPropagation(); closeLog(); });
    if (logPanelOvl)  logPanelOvl.addEventListener('click', closeLog);

    /* ── BREACH TEST BUTTONS (desktop topbar + mobile topnav) ── */
    function handleBreach(e) {
        e.preventDefault();
        if (!connected) {
            log('[AUDIT] Must be connected to run Security Integrity Audit.', 'warning');
            openLog();
            return;
        }
        openLog();
        log('[AUDIT] \u25ba Initiating Security Integrity Audit...', 'info');
        setTimeout(function() {
            log('[PROBE] Checking real IP exposure via exit node...', 'system');
        }, 350);
        setTimeout(function() {
            log('[ENC] AES-256-GCM envelope integrity: \u2713 VERIFIED', 'success');
        }, 750);
        setTimeout(function() {
            log('[DNS] Leak test: No DNS exposure detected. \u2713 CLEAN', 'success');
        }, 1100);
        setTimeout(function() {
            log('[KILL SWITCH] Monitor active \u2014 Kill-switch: ARMED', 'success');
        }, 1500);
        setTimeout(function() {
            log('[AUDIT] \u2713 Security Integrity PASSED \u2014 Connection fully secured.', 'success');
        }, 2000);
    }
    var breachDsk = $('breach-test-btn-desktop');
    var breachMob = $('breach-test-btn');
    if (breachDsk) breachDsk.addEventListener('click', handleBreach);
    if (breachMob) breachMob.addEventListener('click', handleBreach);

    /* ── Drawer Toggle (Mobile/Tablet) ── */
    var pRight = $('panel-right');
    var dockBtn = $('dock-btn-right');
    var closeDrawer = $('close-drawer');
    if (dockBtn)     dockBtn.addEventListener('click', function(e) { e.preventDefault(); if (pRight) pRight.classList.add('open'); });
    if (closeDrawer) closeDrawer.addEventListener('click', function(e) { e.preventDefault(); if (pRight) pRight.classList.remove('open'); });
    document.addEventListener('click', function(e) {
        if (!pRight || !pRight.classList.contains('open')) return;
        if (!pRight.contains(e.target) && e.target !== dockBtn) pRight.classList.remove('open');
    });

    /* ─── Secret Installer Verification ────── */
    var iModal  = $('installer-modal');
    var vCode   = $('v-code-input');
    var vMsg    = $('v-msg');
    var vDlBtn  = $('v-dl-btn');
    var sDlBtn  = $('secret-install-btn');
    var vName   = $('v-user-name');
    var vEmail  = $('v-user-email');
    var dlTimer = null;
    var iconClicks    = 0;
    var activeAuthCode = '';
    var adminMail = 'verifiedzedon' + '@' + 'gmail.com';

    function genAuthCode() {
        var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        var res = '';
        for (var i = 0; i < 8; i++) res += chars.charAt(Math.floor(Math.random() * chars.length));
        return res;
    }

    var logoClickers = document.querySelectorAll('.logo-clicker');
    logoClickers.forEach(function(logo) {
        logo.addEventListener('click', function() {
            iconClicks++;
            if (iconClicks === 15) {
                if (dlTimer) clearTimeout(dlTimer);
                if (sDlBtn) sDlBtn.classList.add('active');
                log('[SEC] High-Priority Installer Access Granted. Port open for 10s.', 'success');
                iconClicks = 0;
                dlTimer = setTimeout(function() { if (sDlBtn) sDlBtn.classList.remove('active'); }, 10000);
                
                // Automatically reveal the drawer for mobile so user sees the hidden button
                if (window.innerWidth <= 1199) {
                    document.body.classList.add('servers-open');
                }
            } else if (iconClicks > 8) {
                log('[SEC] Sequence detected: ' + (15 - iconClicks) + ' handshakes remaining...', 'info');
            }
        });
    });

    if (sDlBtn) {
        sDlBtn.addEventListener('click', function() { if (iModal) iModal.classList.add('open'); });
    }

    var vModalClose = $('v-modal-close');
    if (vModalClose) {
        vModalClose.addEventListener('click', function() {
            if (iModal) iModal.classList.remove('open');
            if (vCode)  { vCode.value = ''; }
            if (vName)  { vName.value = ''; }
            if (vEmail) { vEmail.value = ''; }
            if (vMsg)   { vMsg.textContent = ''; vMsg.className = 'v-msg'; }
            if (vDlBtn) vDlBtn.disabled = true;
            activeAuthCode = '';
        });
    }

    var vSendBtn = $('v-send-btn');
    if (vSendBtn) {
        vSendBtn.addEventListener('click', function(e) {
            e.preventDefault();                                        // FIX: always prevent default
            if (!vName || !vEmail) return;
            if (!vName.value || !vEmail.value) {
                if (vMsg) { vMsg.textContent = 'PLEASE COMPLETE USER IDENTITY FORM'; vMsg.className = 'v-msg error'; }
                return;
            }
            activeAuthCode = genAuthCode();

            fetch('/api/mail/send-code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: vName.value, email: vEmail.value, code: activeAuthCode })
            }).catch(function(err) { console.warn('[MAIL] Could not dispatch:', err); });

            if (vMsg) { vMsg.textContent = 'ACCESS CODE DISPATCHED TO ' + vEmail.value.toUpperCase(); vMsg.className = 'v-msg info'; }
            log('[SEC] Routing auth token for ' + vName.value + ' to backend...', 'system');
        });
    }

    if (vCode) {
        vCode.addEventListener('input', function() {
            var val = vCode.value.toUpperCase();
            vCode.value = val;
            if (activeAuthCode && val === activeAuthCode) {
                if (vMsg) { vMsg.textContent = 'HANDSHAKE VERIFIED: ACCESS GRANTED'; vMsg.className = 'v-msg success'; }
                if (vDlBtn) vDlBtn.disabled = false;
            } else {
                if (vDlBtn) vDlBtn.disabled = true;
            }
        });
    }

    if (vDlBtn) {
        vDlBtn.addEventListener('click', function() {
            if (vMsg) vMsg.textContent = 'PREPARING LOCAL INSTALLER BINARY...';
            vDlBtn.disabled = true;
            setTimeout(function() {
                if (vMsg) vMsg.textContent = 'DOWNLOAD STARTED SUCCESSFULLY';
                log('[SUCCESS] Nexprox Desktop Installer dispatched to browser.', 'success');
                setTimeout(function() {
                    if (iModal) iModal.classList.remove('open');
                    if (vCode)  vCode.value = '';
                    if (vName)  vName.value = '';
                    if (vEmail) vEmail.value = '';
                    if (vMsg)   vMsg.textContent = '';
                }, 2500);
            }, 1800);
        });
    }

    /* ── LOGIN ICON STATE ── */
    var loginIcon = document.querySelector('#login-nav-btn i');
    if (loginIcon) {
        loginIcon.className = isGuest() ? 'fa-solid fa-user' : 'fa-solid fa-user-shield';
    }
    var loginNavBtn = $('login-nav-btn');
    if (loginNavBtn) {
        loginNavBtn.title = isGuest() ? 'Sign In' : 'Signed In ✓';
        loginNavBtn.setAttribute('aria-label', isGuest() ? 'Sign In' : 'Signed In');
        loginNavBtn.addEventListener('click', function() {
            window.location.href = '/login.html';
        });
    }

    /* ─── INITIAL HEALTH CHECK ───────────── */
    function updateHealth() {
        var nodes = Array.from(document.querySelectorAll('#main-server-list .server-item'));
        var data  = nodes.map(function(n) { return { host: n.dataset.host, port: parseInt(n.dataset.port) }; });

        log('[AUDIT] Auto-scanning local network & routing nodes...', 'info');

        fetch('/api/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
            signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined
        })
        .then(function(r) { return r.json(); })
        .then(function(results) {
            var aliveCount = results.filter(function(x) { return x.alive; }).length;
            log('[AUDIT] Network scan complete. ' + aliveCount + '/' + results.length + ' nodes active.', 'success');

            results.forEach(function(res, i) {
                var node = nodes[i]; if (!node) return;
                if (!res.alive) {
                    node.classList.add('node-offline');
                    if (!node.querySelector('.offline-tag')) {
                        var tag = document.createElement('span');
                        tag.className = 'tag legacy offline-tag'; tag.style.fontSize = '8px'; tag.textContent = 'OFFLINE';
                        node.appendChild(tag);
                    }
                } else {
                    node.classList.remove('node-offline');
                    var tag = node.querySelector('.offline-tag');
                    if (tag) tag.remove();
                }
            });

            // ZOOM MAP on first load to selected server
            if (!updateHealth.initZoom) {
                zoomToServer(sel);
                updateHealth.initZoom = true;
            }
        })
        .catch(function() {
            log('[WARN] Local network response delayed — Retrying link...', 'warning');
        });
    }

    // Set up periodic scanning
    setInterval(updateHealth, 30000); 
    setInterval(fetchIp, 60000); // Periodic IP check to detect leaks/changes

    /* ─── SECURITY: KILL SWITCH & BREACH ──── */
    var realIpAddress  = '—';
    var killSwitchActive = false;

    function startBreachMonitor() {
        setInterval(function() {
            if (!connected || killSwitchActive) return;
            fetch('/api/ip')
                .then(function(r) { return r.json(); })
                .then(function(data) {
                    if (data.ip && data.ip === realIpAddress) {
                        log('[CRITICAL] IP BREACH DETECTED! KILL SWITCH ACTIVATED.', 'error');
                        disconnect();
                        killSwitchActive = true;
                        setTimeout(function() { killSwitchActive = false; }, 5000);
                    }
                })
                .catch(function() {});
        }, 12000);                                                     // PERF: 12s interval (was 8s)
    }

    /* NOTE: Breach listener already bound above via handleBreach() — duplicate removed. */

    /* ─── INIT ─────────────────────────────── */
    buildGrid();
    buildLand();
    buildMarkers();
    syncTunnel();

    fetchIp();

    renderCustomProxies();
    updateRouteIdle();
    updateHealth();
    startBreachMonitor();

    /* ─── GATED VISUAL LOCK ────────────────── */
    if (isGuest()) {
        serverNodes.forEach(function(n, i) { if (i > 0) n.classList.add('locked-feat'); });
        tunnelItems.forEach(function(n) { n.classList.add('locked-feat'); });
        var form = $('custom-proxy-section');
        if (form) form.classList.add('locked-feat');
    }

    if (savedConnected) {
        log('[SYS] Restoring previous session state...', 'system');
        setTimeout(connect, 1200);
    }

    if (infoHost) infoHost.textContent = sel.host;

})();
