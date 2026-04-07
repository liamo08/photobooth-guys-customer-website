// ── Header scroll effect ──
const header = document.getElementById('siteHeader');
if (header) {
  window.addEventListener('scroll', () => {
    header.classList.toggle('scrolled', window.scrollY > 40);
  }, { passive: true });
}

// ── Mobile menu ──
const menuToggle = document.getElementById('menuToggle');
const mobileMenu = document.getElementById('mobileMenu');
if (menuToggle && mobileMenu) {
  menuToggle.addEventListener('click', () => {
    menuToggle.classList.toggle('active');
    mobileMenu.classList.toggle('open');
    document.body.style.overflow = mobileMenu.classList.contains('open') ? 'hidden' : '';
  });
}
function closeMobile() {
  if (menuToggle && mobileMenu) {
    menuToggle.classList.remove('active');
    mobileMenu.classList.remove('open');
    document.body.style.overflow = '';
  }
}

// ── Scroll reveal (IntersectionObserver) ──
const revealEls = document.querySelectorAll('.reveal');
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
revealEls.forEach(el => revealObserver.observe(el));

// ── Smooth scroll for anchor links ──
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      closeMobile();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

// ── Cursor glow follower ──
const glow = document.getElementById('cursorGlow');
if (glow) {
  let glowActive = false;
  document.addEventListener('mousemove', (e) => {
    if (!glowActive) { glow.classList.add('active'); glowActive = true; }
    glow.style.left = e.clientX + 'px';
    glow.style.top = e.clientY + 'px';
  });
  document.addEventListener('mouseleave', () => {
    glow.classList.remove('active');
    glowActive = false;
  });
}

// ── Counter animation for hero stat ──
function animateCounter(el, target, suffix) {
  const duration = 2000;
  const start = performance.now();
  const step = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.floor(eased * target).toLocaleString() + suffix;
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const statEl = document.querySelector('.hero-stat-number');
if (statEl) {
  const statObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateCounter(statEl, 2500, '+');
        statObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });
  statObserver.observe(statEl);
}

// ── Service card tilt on mouse move (GPU-accelerated, no forced reflow) ──
document.querySelectorAll('.service-card').forEach(card => {
  let rect = null;
  let ticking = false;
  card.addEventListener('mouseenter', () => {
    rect = card.getBoundingClientRect();
  });
  card.addEventListener('mousemove', (e) => {
    if (!rect || ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      card.style.transform = `translateY(-6px) perspective(600px) rotateX(${y * -4}deg) rotateY(${x * 4}deg)`;
      ticking = false;
    });
  });
  card.addEventListener('mouseleave', () => {
    rect = null;
    card.style.transform = '';
  });
});

// ── FAQ Accordion ──
document.querySelectorAll('.faq-question').forEach(btn => {
  btn.addEventListener('click', () => {
    const item = btn.parentElement;
    const isOpen = item.classList.contains('open');
    // Close all
    document.querySelectorAll('.faq-item.open').forEach(el => el.classList.remove('open'));
    // Toggle clicked
    if (!isOpen) item.classList.add('open');
  });
});

// ── Mobile showcase arrows (waits for dynamic tabs to load) ──
(function() {
  var showcase = document.querySelector('.product-showcase');
  if (!showcase) return;

  var imgWrap = showcase.querySelector('.showcase-image-wrap');
  var tabsEl = showcase.querySelector('.showcase-tabs');
  if (!imgWrap || !tabsEl) return;

  function setup() {
    if (imgWrap.querySelector('.showcase-arrow')) return; // already set up

    var prevBtn = document.createElement('button');
    prevBtn.className = 'showcase-arrow showcase-arrow-prev';
    prevBtn.setAttribute('aria-label', 'Previous feature');
    prevBtn.innerHTML = '<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>';

    var nextBtn = document.createElement('button');
    nextBtn.className = 'showcase-arrow showcase-arrow-next';
    nextBtn.setAttribute('aria-label', 'Next feature');
    nextBtn.innerHTML = '<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18l6-6-6-6"/></svg>';

    imgWrap.appendChild(prevBtn);
    imgWrap.appendChild(nextBtn);

    function navigateShowcase(direction) {
      var tabs = tabsEl.querySelectorAll('.showcase-tab');
      if (tabs.length === 0) return;
      var currentIdx = -1;
      tabs.forEach(function(t, i) { if (t.classList.contains('active')) currentIdx = i; });
      if (currentIdx === -1) currentIdx = 0;
      var nextIdx = (currentIdx + direction + tabs.length) % tabs.length;
      tabs[nextIdx].click();
    }

    prevBtn.addEventListener('click', function(e) { e.stopPropagation(); navigateShowcase(-1); });
    nextBtn.addEventListener('click', function(e) { e.stopPropagation(); navigateShowcase(1); });

    // Swipe support on the image
    var touchStartX = 0;
    imgWrap.addEventListener('touchstart', function(e) { touchStartX = e.changedTouches[0].clientX; }, { passive: true });
    imgWrap.addEventListener('touchend', function(e) {
      if (!window.matchMedia('(max-width: 640px)').matches) return;
      var diff = e.changedTouches[0].clientX - touchStartX;
      if (Math.abs(diff) > 50) {
        navigateShowcase(diff > 0 ? -1 : 1);
      }
    }, { passive: true });
  }

  // Watch for tabs to be populated dynamically
  var observer = new MutationObserver(function() {
    if (tabsEl.querySelectorAll('.showcase-tab').length > 0) {
      observer.disconnect();
      setup();
    }
  });
  observer.observe(tabsEl, { childList: true });
})();

// ── Category filter tabs ──
document.querySelectorAll('.filter-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const category = tab.dataset.category;
    document.querySelectorAll('.service-card-enhanced').forEach(card => {
      if (category === 'all' || card.dataset.category === category) {
        card.style.display = '';
        card.classList.remove('visible');
        void card.offsetWidth;
        card.classList.add('visible');
      } else {
        card.style.display = 'none';
      }
    });
  });
});
