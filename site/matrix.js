// Matrix digital rain + scroll-reactive depth scene
(function() {
  'use strict';

  var prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function clamp01(value) {
    return Math.max(0, Math.min(1, value));
  }

  function initRain() {
    var rainCanvas = document.getElementById('matrix-rain');
    if (!rainCanvas || prefersReducedMotion) return;

    var ctx = rainCanvas.getContext('2d');
    var chars = 'ｦｧｨｩｪｫｬｭｮｯｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>/{}[]|\\:;';
    var fontSize = 15;
    var columns = 0;
    var drops = [];
    var frameHandle = null;
    var lastTime = 0;

    function resize() {
      rainCanvas.width = window.innerWidth;
      rainCanvas.height = window.innerHeight;
      columns = Math.max(1, Math.floor(rainCanvas.width / fontSize));
      drops = [];
      for (var i = 0; i < columns; i++) {
        drops[i] = Math.random() * -120;
      }
    }

    function draw(now) {
      if (now - lastTime < 70) {
        frameHandle = window.requestAnimationFrame(draw);
        return;
      }
      lastTime = now;

      ctx.fillStyle = 'rgba(0, 0, 0, 0.07)';
      ctx.fillRect(0, 0, rainCanvas.width, rainCanvas.height);
      ctx.font = fontSize + 'px monospace';

      for (var i = 0; i < drops.length; i++) {
        var x = i * fontSize;
        var y = drops[i] * fontSize;
        var headChar = chars[Math.floor(Math.random() * chars.length)];

        ctx.fillStyle = 'rgba(195, 255, 210, 0.92)';
        ctx.fillText(headChar, x, y);

        for (var j = 1; j < 6 && drops[i] - j > 0; j++) {
          var alpha = 0.72 - (j * 0.12);
          var trailChar = chars[Math.floor(Math.random() * chars.length)];
          ctx.fillStyle = 'rgba(0, 255, 65, ' + alpha + ')';
          ctx.fillText(trailChar, x, (drops[i] - j) * fontSize);
        }

        if (y > rainCanvas.height && Math.random() > 0.976) {
          drops[i] = Math.random() * -24;
        } else {
          drops[i] += 0.34 + Math.random() * 0.38;
        }
      }

      frameHandle = window.requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener('resize', resize);
    frameHandle = window.requestAnimationFrame(draw);

    window.addEventListener('beforeunload', function() {
      if (frameHandle) window.cancelAnimationFrame(frameHandle);
    });
  }

  function initDepthScene() {
    var canvas3d = document.getElementById('webgl-canvas');
    if (!canvas3d || prefersReducedMotion || typeof THREE === 'undefined') return;

    var renderer = new THREE.WebGLRenderer({
      canvas: canvas3d,
      alpha: true,
      antialias: true,
      powerPreference: 'low-power'
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));

    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 0.8, 8);

    var ambientLight = new THREE.AmbientLight(0x06330f, 1.25);
    scene.add(ambientLight);

    var pointLight = new THREE.PointLight(0x00ff41, 1.6, 60);
    pointLight.position.set(4, 3, 8);
    scene.add(pointLight);

    var grid = new THREE.GridHelper(60, 36, 0x00ff41, 0x003300);
    grid.position.y = -4.5;
    grid.material.transparent = true;
    grid.material.opacity = 0.22;
    scene.add(grid);

    var horizon = new THREE.Mesh(
      new THREE.PlaneGeometry(90, 90, 20, 20),
      new THREE.MeshBasicMaterial({
        color: 0x031706,
        transparent: true,
        opacity: 0.22,
        wireframe: true
      })
    );
    horizon.rotation.x = -Math.PI / 2.2;
    horizon.position.set(0, -6.4, -14);
    scene.add(horizon);

    var particleCount = 220;
    var particleGeometry = new THREE.BufferGeometry();
    var positions = new Float32Array(particleCount * 3);
    var colors = new Float32Array(particleCount * 3);

    for (var i = 0; i < particleCount; i++) {
      var idx = i * 3;
      positions[idx] = (Math.random() - 0.5) * 40;
      positions[idx + 1] = (Math.random() - 0.2) * 18;
      positions[idx + 2] = (Math.random() - 0.5) * 48 - 6;
      colors[idx] = 0.2;
      colors[idx + 1] = 0.75 + Math.random() * 0.2;
      colors[idx + 2] = 0.25;
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particleGeometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    var particles = new THREE.Points(
      particleGeometry,
      new THREE.PointsMaterial({
        size: 0.06,
        vertexColors: true,
        transparent: true,
        opacity: 0.45,
        blending: THREE.AdditiveBlending
      })
    );
    scene.add(particles);

    var targetScroll = 0;
    var scrollProgress = 0;
    var time = 0;

    window.addEventListener('scroll', function() {
      var st = window.scrollY || document.documentElement.scrollTop;
      var dh = document.documentElement.scrollHeight - window.innerHeight;
      targetScroll = clamp01(dh > 0 ? st / dh : 0);
    });

    function animate() {
      window.requestAnimationFrame(animate);
      time += 0.003;

      scrollProgress += (targetScroll - scrollProgress) * 0.06;

      var bar = document.getElementById('progress-bar');
      if (bar) {
        bar.style.width = Math.min(scrollProgress * 100, 100) + '%';
      }

      particles.rotation.y = time * 0.18;
      particles.position.y = Math.sin(time * 2.4) * 0.18;
      horizon.rotation.z = Math.sin(time * 0.5) * 0.02;

      var targetX = Math.sin(scrollProgress * Math.PI * 2.2) * 1.2;
      var targetY = 0.8 - scrollProgress * 1.1;
      var targetZ = 8 - scrollProgress * 6.2;

      camera.position.x += (targetX - camera.position.x) * 0.04;
      camera.position.y += (targetY - camera.position.y) * 0.04;
      camera.position.z += (targetZ - camera.position.z) * 0.04;
      camera.lookAt(0, -1.4, -10);

      pointLight.intensity = 1.3 + scrollProgress * 1.2;
      renderer.render(scene, camera);
    }

    animate();

    window.addEventListener('resize', function() {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    });
  }

  initRain();
  initDepthScene();
})();
