
    (function(){
      "use strict";

      const hamburger = document.getElementById('hamburgerBtn');
      const slideMenu = document.getElementById('slideMenu');
      const overlay = document.getElementById('menuOverlay');

      const STORAGE_KEY = 'draggableHamburgerPos';
      const DEFAULT_LEFT = 20;
      const DEFAULT_BOTTOM = 80;

      let isMenuOpen = false;
      let isDragging = false;
      let hasMoved = false;  // Track if we actually moved during drag
      let startX = 0, startY = 0;
      let initialLeft = 0, initialBottom = 0;
      
      let minLeft = 8;
      let maxLeft = window.innerWidth - 72;
      let minBottom = 8;
      let maxBottom = window.innerHeight - 72;

      function updateDragConstraints() {
        const w = window.innerWidth;
        const h = window.innerHeight;
        const btnWidth = hamburger.offsetWidth || 64;
        const btnHeight = hamburger.offsetHeight || 64;
        maxLeft = Math.max(8, w - btnWidth - 8);
        maxBottom = Math.max(8, h - btnHeight - 8);
      }

      function setPosition(left, bottom) {
        left = Math.min(maxLeft, Math.max(minLeft, left));
        bottom = Math.min(maxBottom, Math.max(minBottom, bottom));
        
        hamburger.style.left = left + 'px';
        hamburger.style.bottom = bottom + 'px';
      }

      function getCurrentPosition() {
        const left = parseFloat(hamburger.style.left) || DEFAULT_LEFT;
        const bottom = parseFloat(hamburger.style.bottom) || DEFAULT_BOTTOM;
        return { left, bottom };
      }

      function savePosition(left, bottom) {
        const pos = { left, bottom };
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(pos));
        } catch(e) {}
      }

      function loadPosition() {
        try {
          const stored = localStorage.getItem(STORAGE_KEY);
          if (stored) {
            const pos = JSON.parse(stored);
            if (typeof pos.left === 'number' && typeof pos.bottom === 'number') {
              return { left: pos.left, bottom: pos.bottom };
            }
          }
        } catch(e) {}
        return null;
      }

      function initializePosition() {
        updateDragConstraints();
        
        const saved = loadPosition();
        let left, bottom;
        if (saved) {
          left = saved.left;
          bottom = saved.bottom;
        } else {
          left = DEFAULT_LEFT;
          bottom = DEFAULT_BOTTOM;
        }
        
        left = Math.min(maxLeft, Math.max(minLeft, left));
        bottom = Math.min(maxBottom, Math.max(minBottom, bottom));
        
        hamburger.style.left = left + 'px';
        hamburger.style.bottom = bottom + 'px';
        
        savePosition(left, bottom);
      }

      function openMenu() {
        slideMenu.classList.add('open');
        overlay.classList.add('active');
        hamburger.classList.add('menu-open');
        isMenuOpen = true;
      }

      function closeMenu() {
        slideMenu.classList.remove('open');
        overlay.classList.remove('active');
        hamburger.classList.remove('menu-open');
        isMenuOpen = false;
      }

      function toggleMenu(e) {
        // Only toggle if we didn't just finish dragging
        if (!hasMoved) {
          if (isMenuOpen) {
            closeMenu();
          } else {
            openMenu();
          }
        }
        hasMoved = false;  // Reset for next interaction
      }

      // Pointer event handlers
      function onPointerDown(e) {
        e.preventDefault();
        hamburger.setPointerCapture(e.pointerId);
        
        startX = e.clientX;
        startY = e.clientY;
        
        const left = parseFloat(hamburger.style.left);
        const bottom = parseFloat(hamburger.style.bottom);
        
        initialLeft = isNaN(left) ? DEFAULT_LEFT : left;
        initialBottom = isNaN(bottom) ? DEFAULT_BOTTOM : bottom;
        
        updateDragConstraints();
        
        isDragging = true;
        hasMoved = false;
        hamburger.style.cursor = 'grabbing';
        hamburger.style.transition = 'none';
      }

      function onPointerMove(e) {
        if (!isDragging) return;
        e.preventDefault();
        
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        
        // Check if we've moved significantly (more than 3px)
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
          hasMoved = true;
        }
        
        let newLeft = initialLeft + dx;
        let newBottom = initialBottom - dy;
        
        newLeft = Math.min(maxLeft, Math.max(minLeft, newLeft));
        newBottom = Math.min(maxBottom, Math.max(minBottom, newBottom));
        
        hamburger.style.left = newLeft + 'px';
        hamburger.style.bottom = newBottom + 'px';
      }

      function onPointerUp(e) {
        if (!isDragging) return;
        e.preventDefault();
        
        isDragging = false;
        hamburger.style.cursor = 'grab';
        hamburger.style.transition = '';
        hamburger.releasePointerCapture(e.pointerId);
        
        const left = parseFloat(hamburger.style.left);
        const bottom = parseFloat(hamburger.style.bottom);
        if (!isNaN(left) && !isNaN(bottom)) {
          savePosition(left, bottom);
        }
        
        // If we didn't move, this was a click/tap
        if (!hasMoved) {
          toggleMenu(e);
        }
        hasMoved = false;
      }

      function onPointerCancel(e) {
        if (isDragging) {
          isDragging = false;
          hamburger.style.cursor = 'grab';
          hamburger.style.transition = '';
          hamburger.releasePointerCapture(e.pointerId);
          
          const left = parseFloat(hamburger.style.left);
          const bottom = parseFloat(hamburger.style.bottom);
          if (!isNaN(left) && !isNaN(bottom)) {
            savePosition(left, bottom);
          }
        }
        hasMoved = false;
      }

      // Close menu when clicking overlay
      overlay.addEventListener('click', closeMenu);

      // Handle window resize
      window.addEventListener('resize', () => {
        updateDragConstraints();
        const pos = getCurrentPosition();
        setPosition(pos.left, pos.bottom);
      });

      // Add event listeners
      hamburger.addEventListener('pointerdown', onPointerDown);
      hamburger.addEventListener('pointermove', onPointerMove);
      hamburger.addEventListener('pointerup', onPointerUp);
      hamburger.addEventListener('pointercancel', onPointerCancel);

      // Initialize
      initializePosition();
    })();