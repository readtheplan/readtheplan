// ── Matrix Digital Rain + 3D Scene ──
(function() {
  'use strict';

  // ── Digital Rain ──
  var rainCanvas = document.getElementById('matrix-rain');
  if (rainCanvas) {
    var ctx = rainCanvas.getContext('2d');
    var chars = 'ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>/{}[]|\\:;';
    var fontSize = 14;
    var columns = 0;
    var drops = [];

    function initRain() {
      rainCanvas.width = window.innerWidth;
      rainCanvas.height = window.innerHeight;
      columns = Math.floor(rainCanvas.width / fontSize);
      drops = [];
      for (var i = 0; i < columns; i++) {
        drops[i] = Math.random() * -100;
      }
    }

    function drawRain() {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, rainCanvas.width, rainCanvas.height);

      ctx.font = fontSize + 'px monospace';

      for (var i = 0; i < drops.length; i++) {
        var text = chars[Math.floor(Math.random() * chars.length)];

        // Brighter head
        ctx.fillStyle = 'rgba(180, 255, 180, 0.9)';
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Trailing characters with fade
        for (var j = 1; j < 5 && drops[i] - j > 0; j++) {
          var alpha = 0.9 - (j * 0.18);
          ctx.fillStyle = 'rgba(0, 255, 65, ' + alpha + ')';
          var trailChar = chars[Math.floor(Math.random() * chars.length)];
          ctx.fillText(trailChar, i * fontSize, (drops[i] - j) * fontSize);
        }

        if (drops[i] * fontSize > rainCanvas.height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 0.3 + Math.random() * 0.5;
      }
    }

    initRain();
    window.addEventListener('resize', initRain);
    setInterval(drawRain, 50);
  }

  // ── Three.js 3D Scene ──
  var canvas3d = document.getElementById('webgl-canvas');
  if (!canvas3d) return;

  var renderer = new THREE.WebGLRenderer({ canvas: canvas3d, alpha: true, antialias: true });
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  var scene = new THREE.Scene();
  var camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
  camera.position.set(0, 0, 5);

  // Green ambient
  var ambientLight = new THREE.AmbientLight(0x003300, 0.6);
  scene.add(ambientLight);

  var pointLight1 = new THREE.PointLight(0x00FF41, 2.5, 50);
  pointLight1.position.set(5, 5, 5);
  scene.add(pointLight1);

  var pointLight2 = new THREE.PointLight(0x008F11, 1.5, 50);
  pointLight2.position.set(-5, -3, 3);
  scene.add(pointLight2);

  var pointLight3 = new THREE.PointLight(0x00CC33, 1, 50);
  pointLight3.position.set(0, 8, -2);
  scene.add(pointLight3);

  var shapes = [];
  var greenColors = [0x00FF41, 0x00CC33, 0x008F11, 0x006622, 0x00AA22, 0x00FF41, 0x00CC33, 0x006622];
  var geometries = [
    new THREE.IcosahedronGeometry(0.6, 0),
    new THREE.BoxGeometry(0.8, 0.8, 0.8),
    new THREE.OctahedronGeometry(0.5, 0),
    new THREE.TorusGeometry(0.4, 0.15, 16, 32),
    new THREE.DodecahedronGeometry(0.5, 0),
    new THREE.ConeGeometry(0.5, 1, 8),
    new THREE.TorusKnotGeometry(0.3, 0.1, 64, 16),
    new THREE.SphereGeometry(0.4, 16, 16)
  ];

  for (var i = 0; i < 20; i++) {
    var color = greenColors[i % greenColors.length];
    var mat = new THREE.MeshPhysicalMaterial({
      color: color,
      metalness: 0.2,
      roughness: 0.35,
      transparent: true,
      opacity: 0.6,
      emissive: color,
      emissiveIntensity: 0.25
    });
    var mesh = new THREE.Mesh(geometries[i % geometries.length], mat);
    mesh.position.set((Math.random() - 0.5) * 20, (Math.random() - 0.5) * 12, (Math.random() - 0.5) * 15 - 3);
    mesh.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, 0);
    mesh.userData = {
      rot: { x: (Math.random() - 0.5) * 0.015, y: (Math.random() - 0.5) * 0.015 },
      baseY: mesh.position.y,
      speed: 0.001 + Math.random() * 0.003,
      range: 0.5 + Math.random() * 2
    };
    scene.add(mesh);
    shapes.push(mesh);
  }

  // Green particle field
  var pc = 800;
  var pGeo = new THREE.BufferGeometry();
  var pos = new Float32Array(pc * 3);
  var col = new Float32Array(pc * 3);
  for (var j = 0; j < pc * 3; j += 3) {
    pos[j] = (Math.random() - 0.5) * 50;
    pos[j + 1] = (Math.random() - 0.5) * 50;
    pos[j + 2] = (Math.random() - 0.5) * 50;
    col[j] = 0;
    col[j + 1] = 0.5 + Math.random() * 0.5;
    col[j + 2] = 0;
  }
  pGeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  pGeo.setAttribute('color', new THREE.BufferAttribute(col, 3));
  var particles = new THREE.Points(pGeo, new THREE.PointsMaterial({
    size: 0.05,
    vertexColors: true,
    transparent: true,
    opacity: 0.7,
    blending: THREE.AdditiveBlending
  }));
  scene.add(particles);

  // Green grid
  var grid = new THREE.GridHelper(40, 40, 0x00FF41, 0x003300);
  grid.position.y = -4;
  grid.material.transparent = true;
  grid.material.opacity = 0.25;
  scene.add(grid);

  // ── Scroll-reactive camera ──
  var time = 0;
  var scrollProgress = 0;
  var targetScroll = 0;

  window.addEventListener('scroll', function () {
    var st = window.scrollY || document.documentElement.scrollTop;
    var dh = document.documentElement.scrollHeight - window.innerHeight;
    targetScroll = dh > 0 ? st / dh : 0;
  });

  function animate() {
    requestAnimationFrame(animate);
    time += 0.005;

    // Smooth scroll tracking
    scrollProgress += (targetScroll - scrollProgress) * 0.08;

    // Progress bar
    var bar = document.getElementById('progress-bar');
    if (bar) {
      bar.style.width = Math.min(scrollProgress * 100, 100) + '%';
    }

    // Rotate shapes
    shapes.forEach(function(m) {
      m.rotation.x += m.userData.rot.x;
      m.rotation.y += m.userData.rot.y;
      m.position.y = m.userData.baseY + Math.sin(time * m.userData.speed * 1000) * m.userData.range;
    });

    // Rotate particle field
    particles.rotation.y += 0.0003;
    particles.rotation.x += 0.00015;

    // Scroll-reactive camera — move through 3D space as user scrolls
    var tz = 5 - scrollProgress * 10;
    var tx = Math.sin(scrollProgress * Math.PI * 4) * 4;
    var ty = Math.cos(scrollProgress * Math.PI * 2) * 2.5;
    camera.position.x += (tx - camera.position.x) * 0.04;
    camera.position.y += (ty - camera.position.y) * 0.04;
    camera.position.z += (tz - camera.position.z) * 0.04;
    camera.lookAt(0, 0, 0);

    // Lights intensify with scroll
    pointLight1.intensity = 2 + scrollProgress * 3;
    pointLight2.intensity = 1 + scrollProgress * 2;
    pointLight3.intensity = 0.8 + scrollProgress * 1.5;

    renderer.render(scene, camera);
  }
  animate();

  window.addEventListener('resize', function () {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  });
})();
