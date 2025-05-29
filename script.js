class SecureSession {
  constructor() {
    this.sessionKey = this.generateSessionKey();
    this.isActive = false;
    this.lastActivity = Date.now();
    this.timeout = 30 * 60 * 1000; // 30 minutes
  }

  generateSessionKey() {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  startSession(userKey) {
    if (this.validateUserKey(userKey)) {
      this.isActive = true;
      this.lastActivity = Date.now();
      return true;
    }
    return false;
  }

  validateUserKey(key) {
    const minLength = 12;
    const hasNumbers = /\d/.test(key);
    const hasLetters = /[a-zA-Z]/.test(key);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(key);

    return key.length >= minLength && hasNumbers && hasLetters && hasSpecial;
  }

  checkSession() {
    if (!this.isActive) return false;
    if (Date.now() - this.lastActivity > this.timeout) {
      this.endSession();
      return false;
    }
    this.lastActivity = Date.now();
    return true;
  }

  endSession() {
    this.isActive = false;
    // Clear sensitive data
    document.querySelectorAll('input[type="password"]').forEach(input => {
      input.value = '';
    });
    sessionStorage.removeItem('encrypted-api-key');
  }
}

class RateLimiter {
  constructor(maxRequests = 10, timeWindow = 60000) {
    this.requests = [];
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
  }

  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);

    if (this.requests.length >= this.maxRequests) {
      return false;
    }

    this.requests.push(now);
    return true;
  }

  getRemainingTime() {
    if (this.requests.length < this.maxRequests) return 0;
    const oldestRequest = Math.min(...this.requests);
    return Math.max(0, this.timeWindow - (Date.now() - oldestRequest));
  }
}

// Security utility functions
function encryptApiKey(apiKey, userKey) {
  try {
    return btoa(apiKey.split('').map((char, i) =>
      String.fromCharCode(char.charCodeAt(0) ^ userKey.charCodeAt(i % userKey.length))
    ).join(''));
  } catch (e) {
    console.error('Encryption failed:', e);
    return null;
  }
}

function decryptApiKey(encrypted, userKey) {
  try {
    const decoded = atob(encrypted);
    return decoded.split('').map((char, i) =>
      String.fromCharCode(char.charCodeAt(0) ^ userKey.charCodeAt(i % userKey.length))
    ).join('');
  } catch (e) {
    console.error('Decryption failed:', e);
    return null;
  }
}

function validateUserKey(key) {
  const minLength = 12;
  const hasNumbers = /\d/.test(key);
  const hasLetters = /[a-zA-Z]/.test(key);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(key);

  if (key.length < minLength) {
    throw new Error('Access key must be at least 12 characters long');
  }
  if (!hasNumbers || !hasLetters) {
    throw new Error('Access key must contain both letters and numbers');
  }
  if (!hasSpecial) {
    throw new Error('Access key should contain special characters for better security');
  }

  // Additional check for Firebase collection name compatibility
  const safeCollectionName = createSafeCollectionName(key);
  if (safeCollectionName.length < 3) {
    throw new Error('Access key must result in a valid collection name (at least 3 characters after processing)');
  }

  return true;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

async function encryptData(data, userKey) {
  try {
    // Check data size before encryption
    const dataString = JSON.stringify(data);
    const sizeInMB = new Blob([dataString]).size / (1024 * 1024);
    
    if (sizeInMB > 1) {
      console.warn('Data size is large:', sizeInMB.toFixed(2), 'MB');
    }

    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(userKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('secure-tutorial-progress-2024'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(dataString)
    );

    return {
      data: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv)
    };
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Failed to encrypt data: ' + error.message);
  }
}

async function decryptData(encryptedData, userKey) {
  try {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(userKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('secure-tutorial-progress-2024'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encryptedData.iv) },
      key,
      new Uint8Array(encryptedData.data)
    );

    return JSON.parse(decoder.decode(decrypted));
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt data: ' + error.message);
  }
}

// Main Application Code
const firebaseConfig = {
  authDomain: "application-fcab2.firebaseapp.com",
  projectId: "application-fcab2",
  storageBucket: "application-fcab2.firebasestorage.app",
  messagingSenderId: "984530576038",
  appId: "1:984530576038:web:e08ab589eb035b4d380a67"
};

// Global variables
let db = null;
let firebaseInitialized = false;

let userKey = '';
let isOnlineMode = false;
let isDataLoaded = false;

// Security instances
const secureSession = new SecureSession();
const syncLimiter = new RateLimiter(5, 60000); // 5 requests per minute
const configLimiter = new RateLimiter(3, 300000); // 3 attempts per 5 minutes











const titleContent = document.title;

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", async () => {
  //console.log('DOM loaded, initializing with enhanced security...');

  // Load user key from localStorage
  userKey = localStorage.getItem('firebase-user-key') || '';

  // Load local data first
  loadCompletedSections();
  setupEventListeners();
  setupNavigation();
  setupFAB();
  updateCharacterCounters();
  setupSecurityFeatures();

  // Check if user has configured Firebase
  if (userKey) {
    const encryptedApiKey = sessionStorage.getItem('encrypted-api-key');
    if (encryptedApiKey) {
      try {
        const apiKey = decryptApiKey(encryptedApiKey, userKey);
        if (apiKey) {
          await initializeFirebase(apiKey);
          if (firebaseInitialized) {
            console.log('Firebase initialized from session, loading data...');
            isOnlineMode = true;
            updateSyncStatus('Connecting...', 'syncing');
            await loadFromFirebase();
            return;
          }
        }
      } catch (error) {
        console.error('Failed to restore Firebase session:', error);
      }
    }

    // If we reach here, need to re-configure Firebase
    updateSyncStatus('Offline - Reconfigure needed', 'error');
    setTimeout(() => showFirebaseModal(), 1000);
  } else {
    console.log('No user key found, showing Firebase modal...');
    updateSyncStatus('Offline', 'error');
    setTimeout(() => showFirebaseModal(), 2000);
  }
});

function setupSecurityFeatures() {
  // Session timeout check
  setInterval(() => {
    if (isOnlineMode && userKey && !secureSession.checkSession()) {
      console.log('Session expired, switching to offline mode');
      isOnlineMode = false;
      updateSyncStatus('Session expired - Please reconfigure', 'error');
      setTimeout(() => showFirebaseModal(), 2000);
    }
  }, 60000); // Check every minute

  // Clear clipboard after password input
  document.addEventListener('paste', (e) => {
    if (e.target.type === 'password') {
      setTimeout(() => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText('').catch(() => { });
        }
      }, 30000); // Clear clipboard after 30 seconds
    }
  });

  // Prevent context menu on password fields
  document.querySelectorAll('input[type="password"]').forEach(input => {
    input.addEventListener('contextmenu', (e) => e.preventDefault());
  });
}

async function initializeFirebase(apiKey) {
  try {
    // Clear any existing Firebase apps first
    if (typeof firebase !== 'undefined' && firebase.apps && firebase.apps.length > 0) {
      await Promise.all(firebase.apps.map(app => app.delete()));
    }

    const config = {
      ...firebaseConfig,
      apiKey: apiKey.trim()
    };

    console.log('Attempting Firebase initialization...');

    // Initialize Firebase app
    const app = firebase.initializeApp(config);
    
    // Initialize Firestore
    db = firebase.firestore(app);

    // Test connection with a simple operation
    try {
      await db.collection('progress').limit(1).get();
      console.log('Firebase connection test successful');
    } catch (testError) {
      // Permission denied is expected for security rules, but means connection works
      if (testError.code !== 'permission-denied') {
        throw testError;
      }
      console.log('Firebase connected (permission-denied is normal for test query)');
    }

    firebaseInitialized = true;
    console.log('Firebase initialized successfully');
    return true;

  } catch (error) {
    console.error('Firebase initialization failed:', error);
    
    // Clean up on failure
    if (typeof firebase !== 'undefined' && firebase.apps && firebase.apps.length > 0) {
      try {
        await Promise.all(firebase.apps.map(app => app.delete()));
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }
    }

    firebaseInitialized = false;
    db = null;

    // Better error messages
    if (error.code === 'auth/invalid-api-key') {
      throw new Error('Invalid API key format');
    } else if (error.code === 'auth/api-key-not-valid') {
      throw new Error('API key is not valid for this project');
    } else if (error.message && error.message.includes('network')) {
      throw new Error('Network connection failed');
    } else {
      throw new Error('Failed to connect: ' + (error.message || 'Unknown error'));
    }
  }
}




function setupEventListeners() {
  // Export/Import buttons
  const exportButton = document.getElementById("exportButton");
  const importButton = document.getElementById("importButton");
  const importDataButton = document.getElementById("importDataButton");
  const firebaseButton = document.getElementById("firebaseButton");

  if (exportButton) {
    exportButton.addEventListener("click", exportData);
  }

  if (importDataButton) {
    importDataButton.addEventListener("click", () => importButton?.click());
  }

  if (importButton) {
    importButton.addEventListener("change", handleFileImport);
  }

  if (firebaseButton) {
    firebaseButton.addEventListener("click", showFirebaseModal);
  }

  // Setup all functionality
  setupSectionListeners();
  setupNotesTools();
}





function setupSectionListeners() {
  const pagePath = window.location.pathname;

  document.querySelectorAll(".video-section").forEach((section) => {
    const completeButton = section.querySelector(".complete-btn");
    const unmarkButton = section.querySelector(".unmark-btn");
    const notesTextArea = section.querySelector(".notes-input");

    if (completeButton) {
      completeButton.addEventListener("click", () => {
        try {
          localStorage.setItem(`${pagePath}-${section.id}`, "completed");
        } catch (error) {
          console.warn('LocalStorage not available');
          section.dataset.completed = "true";
        }
        updateSectionStyle(section, true);
        updateSectionCompletion(section, true);
      });
    }

    if (unmarkButton) {
      unmarkButton.addEventListener("click", () => {
        try {
          localStorage.removeItem(`${pagePath}-${section.id}`);
        } catch (error) {
          console.warn('LocalStorage not available');
          delete section.dataset.completed;
        }
        updateSectionStyle(section, false);
        updateSectionCompletion(section, false);
      });
    }

    if (notesTextArea) {
      // Debounced input handler
      let notesSaveTimeout;
      notesTextArea.addEventListener("input", (e) => {
        updateCharacterCounter(e.target);
        try {
          localStorage.setItem(`${pagePath}-notes-${section.id}`, e.target.value);
        } catch (error) {
          console.warn('LocalStorage not available');
        }
        clearTimeout(notesSaveTimeout);
        notesSaveTimeout = setTimeout(() => {
          saveNotes(section, e.target.value);
        }, 1000); // Wait 1 second after user stops typing
      });
    }
  });
}

function setupFAB() {
  const mainFab = document.getElementById("mainFab");
  const fabMenu = document.querySelector(".fab-menu");

  if (mainFab && fabMenu) {
    mainFab.addEventListener("click", () => {
      fabMenu.classList.toggle("active");
    });

    // Close FAB menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!fabMenu.contains(e.target)) {
        fabMenu.classList.remove("active");
      }
    });
  }
}











// Firebase Functions
function showFirebaseModal() {
  const modal = document.getElementById('firebaseModal');
  const userKeyInput = document.getElementById('userKey');

  if (userKey) {
    userKeyInput.value = userKey;
  }

  modal.style.display = 'block';

  // Focus on first empty field
  setTimeout(() => {
    const apiKeyInput = document.getElementById('apiKey');
    if (!apiKeyInput.value) {
      apiKeyInput.focus();
    } else if (!userKeyInput.value) {
      userKeyInput.focus();
    }
  }, 100);
}

function closeFirebaseModal() {
  const modal = document.getElementById('firebaseModal');
  modal.style.display = 'none';

  // Clear sensitive inputs
  const apiKeyInput = document.getElementById('apiKey');
  if (apiKeyInput) {
    apiKeyInput.value = '';
  }
}

async function saveFirebaseConfig() {
  if (!configLimiter.canMakeRequest()) {
    const remainingTime = Math.ceil(configLimiter.getRemainingTime() / 1000);
    showModalStatus(`Too many attempts. Try again in ${remainingTime} seconds`, 'error');
    return;
  }

  const userKeyInput = document.getElementById('userKey');
  const apiKeyInput = document.getElementById('apiKey');
  const newUserKey = sanitizeInput(userKeyInput.value.trim());
  const apiKey = apiKeyInput.value.trim();

  if (!newUserKey || !apiKey) {
    showModalStatus('Please enter both access key and API key', 'error');
    return;
  }

  try {
    // Validate user key
    validateUserKey(newUserKey);

    // Validate API key format (Firebase Web API keys start with 'AIza')
    if (!apiKey.startsWith('AIza') || apiKey.length < 35) {
      throw new Error('Invalid Firebase API key format. Web API keys should start with "AIza"');
    }

    showModalStatus('Validating configuration...', 'success');

    // Test Firebase connection with timeout
    const connectionPromise = initializeFirebase(apiKey);
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Connection timeout after 15 seconds')), 15000)
    );

    const success = await Promise.race([connectionPromise, timeoutPromise]);

    if (!success) {
      throw new Error('Failed to connect to Firebase. Verify your API key and internet connection.');
    }

    // Start secure session
    if (!secureSession.startSession(newUserKey)) {
      throw new Error('Failed to start secure session');
    }

    // Save encrypted API key to session storage
    const encryptedApiKey = encryptApiKey(apiKey, newUserKey);
    if (!encryptedApiKey) {
      throw new Error('Failed to encrypt API key');
    }

    sessionStorage.setItem('encrypted-api-key', encryptedApiKey);
    userKey = newUserKey;
    localStorage.setItem('firebase-user-key', userKey);
    isOnlineMode = true;

    // Clear inputs immediately
    apiKeyInput.value = '';
    userKeyInput.value = '';

    showModalStatus('Configuration saved successfully!', 'success');

    setTimeout(() => {
      closeFirebaseModal();
      loadFromFirebase();
    }, 1500);

  } catch (error) {
    console.error('Firebase configuration error:', error);
    showModalStatus(`Configuration error: ${error.message}`, 'error');

    // Clean up on failure
    if (firebase.apps.length > 0) {
      try {
        await Promise.all(firebase.apps.map(app => app.delete()));
      } catch (e) {
        console.error('Cleanup error:', e);
      }
    }
    firebaseInitialized = false;
    db = null;
    isOnlineMode = false;
  }
}

function showModalStatus(message, type) {
  const modalStatus = document.getElementById('modalStatus');
  modalStatus.textContent = message;
  modalStatus.className = `status-message status-${type}`;
  modalStatus.style.display = 'block';

  // Auto-hide after 5 seconds for errors, 3 for success
  const hideDelay = type === 'error' ? 5000 : 3000;
  setTimeout(() => {
    modalStatus.style.display = 'none';
  }, hideDelay);
}

async function syncToFirebase() {
  if (!db || !userKey || !firebaseInitialized) {
    updateSyncStatus('Configure Firebase first', 'error');
    return;
  }

  if (!secureSession.checkSession()) {
    updateSyncStatus('Session expired', 'error');
    isOnlineMode = false;
    return;
  }

  if (!syncLimiter.canMakeRequest()) {
    const remainingTime = Math.ceil(syncLimiter.getRemainingTime() / 1000);
    updateSyncStatus(`Rate limited. Wait ${remainingTime}s`, 'error');
    return;
  }

  updateSyncStatus('Syncing...', 'syncing');

  try {
    const pagePath = window.location.pathname;
    const tutorialName = getTutorialNameFromPath();
    const collectionName = createSafeCollectionName(userKey);
    const localData = {};

    // Collect all local data for current page
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(pagePath) && key !== 'firebase-user-key') {
        localData[key] = localStorage.getItem(key);
      }
    }

    console.log('Syncing to collection:', collectionName, 'document:', tutorialName);

    // Encrypt data before sending
    const encryptedData = await encryptData(localData, userKey);

    // Save to Firebase: Collection = AccessKey, Document = TutorialName
    let retryCount = 0;
    const maxRetries = 3;

    while (retryCount < maxRetries) {
      try {
        await db.collection(collectionName).doc(tutorialName).set({
          tutorialName: tutorialName,
          originalPath: pagePath,
          fullUrl: window.location.href,
          accessKey: userKey, // Store for verification
          data: encryptedData,
          lastUpdated: firebase.firestore.FieldValue.serverTimestamp(),
          version: '2.0',
          createdAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true }); // Use merge to update existing documents
        
        break;
      } catch (retryError) {
        retryCount++;
        if (retryCount >= maxRetries) {
          throw retryError;
        }
        await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
      }
    }

    updateSyncStatus('Synced successfully', 'synced');
    console.log('Data synced to:', `${collectionName}/${tutorialName}`);
    
    setTimeout(() => {
      if (isOnlineMode) {
        updateSyncStatus('Online', 'synced');
      }
    }, 2000);

  } catch (error) {
    console.error('Sync error:', error);
    let errorMessage = 'Sync failed';

    if (error.code === 'permission-denied') {
      errorMessage = 'Permission denied - Check Firebase security rules';
    } else if (error.code === 'unavailable') {
      errorMessage = 'Firebase unavailable';
    } else if (error.message && error.message.includes('network')) {
      errorMessage = 'Network error';
    }

    updateSyncStatus(errorMessage, 'error');
  }
}

async function loadFromFirebase() {
  if (!db || !userKey || !firebaseInitialized) {
    console.log('Cannot load from Firebase: missing requirements');
    return;
  }

  if (!secureSession.checkSession()) {
    updateSyncStatus('Session expired', 'error');
    isOnlineMode = false;
    return;
  }

  updateSyncStatus('Loading from cloud...', 'syncing');

  try {
    const pagePath = window.location.pathname;
    const tutorialName = getTutorialNameFromPath();
    const collectionName = createSafeCollectionName(userKey);
    
    console.log('Loading from collection:', collectionName, 'document:', tutorialName);
    
    const doc = await db.collection(collectionName).doc(tutorialName).get();

    if (doc.exists) {
      const firebaseData = doc.data();
      
      // Verify this data belongs to the correct user
      if (firebaseData.accessKey !== userKey) {
        throw new Error('Data verification failed - access key mismatch');
      }
      
      let savedData = {};

      // Check if data is encrypted (version 2.0+)
      if (firebaseData.version === '2.0' && firebaseData.data && firebaseData.data.data && firebaseData.data.iv) {
        console.log('Loading encrypted data from Firebase...');
        savedData = await decryptData(firebaseData.data, userKey);
      } else if (firebaseData.data) {
        // Legacy unencrypted data
        console.log('Loading legacy data from Firebase...');
        savedData = firebaseData.data;
      }

      console.log('Loaded data keys:', Object.keys(savedData));

      // Clear existing localStorage data for current page only
      const keysToRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && key.startsWith(pagePath) && key !== 'firebase-user-key') {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));

      // Load data into localStorage
      Object.entries(savedData).forEach(([key, value]) => {
        try {
          localStorage.setItem(key, typeof value === "string" ? value : String(value));
        } catch (error) {
          console.warn('Failed to load item to localStorage:', key, error);
        }
      });

      // Refresh the UI
      loadCompletedSections();
      isDataLoaded = true;

      updateSyncStatus('Data loaded successfully', 'synced');
      setTimeout(() => {
        updateSyncStatus('Online', 'synced');
      }, 2000);
      
    } else {
      console.log('No cloud data found for:', `${collectionName}/${tutorialName}`);
      updateSyncStatus('No cloud data found', 'synced');
      setTimeout(() => {
        updateSyncStatus('Online', 'synced');
      }, 2000);
    }

  } catch (error) {
    console.error('Load error:', error);
    updateSyncStatus('Load failed - ' + error.message, 'error');
  }
}

function updateSyncStatus(message, status) {
  const syncStatus = document.getElementById('syncStatus');
  const syncStatusText = document.getElementById('syncStatusText');

  if (syncStatus && syncStatusText) {
    syncStatusText.textContent = message;
    syncStatus.className = `sync-status ${status}`;
    syncStatus.style.display = 'block';

    console.log('Sync status:', message, status);
  }
}

function updateSectionCompletion(section, isComplete) {
  const pagePath = window.location.pathname;
  const sectionId = section.id;

  try {
    if (isComplete) {
      localStorage.setItem(`${pagePath}-${sectionId}`, "completed");
    } else {
      localStorage.removeItem(`${pagePath}-${sectionId}`);
    }

    updateSectionStyle(section, isComplete);

    // Auto-sync if online mode is enabled
    if (isOnlineMode && firebaseInitialized) {
      setTimeout(syncToFirebase, 500);
    }
  } catch (error) {
    console.warn('LocalStorage not available:', error);
  }
}

function saveNotes(section, value) {
  const pagePath = window.location.pathname;
  const sectionId = section.id;
  const sanitizedValue = sanitizeInput(value);

  try {
    if (sanitizedValue.trim()) {
      localStorage.setItem(`${pagePath}-notes-${sectionId}`, sanitizedValue);
    } else {
      localStorage.removeItem(`${pagePath}-notes-${sectionId}`);
    }

    // Auto-sync if online mode is enabled
    if (isOnlineMode && firebaseInitialized) {
      setTimeout(syncToFirebase, 2000); // Longer delay for notes
    }
  } catch (error) {
    console.warn('LocalStorage not available:', error);
  }
}














function setupNavigation() {
  const navCarousel = document.getElementById("navCarousel");
  const leftScroll = document.getElementById("leftScroll");
  const rightScroll = document.getElementById("rightScroll");

  if (!navCarousel || !leftScroll || !rightScroll) return;

  // Auto-scroll to active item on page load
  const activeItem = navCarousel.querySelector('.nav-item.active');
  if (activeItem) {
    activeItem.scrollIntoView({
      behavior: 'smooth',
      block: 'nearest',
      inline: 'center'
    });
  }

  // Function to update scroll button states
  function updateScrollButtons() {
    const scrollLeft = navCarousel.scrollLeft;
    const scrollWidth = navCarousel.scrollWidth;
    const clientWidth = navCarousel.clientWidth;

    leftScroll.disabled = scrollLeft <= 0;
    rightScroll.disabled = scrollLeft >= scrollWidth - clientWidth - 1;
  }

  // Scroll functions
  function scrollLeftNav() {
    if (!leftScroll.disabled) {
      navCarousel.scrollBy({ left: -200, behavior: "smooth" });
    }
  }

  function scrollRightNav() {
    if (!rightScroll.disabled) {
      navCarousel.scrollBy({ left: 200, behavior: "smooth" });
    }
  }

  // Event listeners
  leftScroll.addEventListener("click", scrollLeftNav);
  rightScroll.addEventListener("click", scrollRightNav);
  navCarousel.addEventListener('scroll', updateScrollButtons);
  window.addEventListener('resize', updateScrollButtons);

  // Update buttons when navigation items are clicked
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
      });
      e.target.closest('.nav-item').classList.add('active');
      setTimeout(updateScrollButtons, 100);
    });
  });

  updateScrollButtons();
}

function updateCharacterCounters() {
  document.querySelectorAll(".notes-input").forEach(textarea => {
    updateCharacterCounter(textarea);
  });
}

function updateCharacterCounter(textarea) {
  const section = textarea.closest(".video-section");
  const counter = section?.querySelector(".char-count");
  if (counter) {
    counter.textContent = textarea.value.length;
  }
}

function exportData() {
  const pagePath = window.location.pathname;
  const localStorageData = {};

  try {
    // Export all localStorage data for current page
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(pagePath)) {
        localStorageData[key] = localStorage.getItem(key);
      }
    }
  } catch (error) {
    console.warn('LocalStorage not available for export');
    alert('Export functionality requires localStorage support');
    return;
  }

  // Add metadata
  const exportData = {
    metadata: {
      exportDate: new Date().toISOString(),
      version: '2.0',
      pagePath: pagePath,
      userKey: userKey ? 'CONFIGURED' : 'NOT_CONFIGURED'
    },
    data: localStorageData
  };

  const blob = new Blob([JSON.stringify(localStorageData, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = `${titleContent.replace(/[^a-z0-9]/gi, '_')}_backup.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function handleFileImport(event) {
  const file = event.target.files[0];
  if (!file) return;

  const pagePath = window.location.pathname;
  const reader = new FileReader();

  reader.onload = function (e) {
    try {
      const jsonData = JSON.parse(e.target.result);


      // Handle both new format (with metadata) and legacy format
      let dataToImport = {};
      if (jsonData.metadata && jsonData.data) {
        // New format with metadata
        console.log('Importing new format data:', jsonData.metadata);
        dataToImport = jsonData.data;
      } else {
        // Legacy format
        console.log('Importing legacy format data');
        dataToImport = jsonData;
      }

      let importedCount = 0;
      Object.entries(dataToImport).forEach(([key, value]) => {
        if (key.startsWith(pagePath)) {
          try {
            const sanitizedValue = typeof value === "string" ?
              sanitizeInput(value.replace(/\\n/g, "\n")) : value;
            localStorage.setItem(key, sanitizedValue);
            importedCount++;
          } catch (error) {
            console.warn('Failed to import item:', key, error);
          }
        }
      });

      alert(`Data imported successfully! ${importedCount} items restored.`);
      location.reload();
    } catch (error) {
      console.error("Import error:", error);
      alert("Error importing data. Please check the file format.");
    }
  };
  reader.readAsText(file);

  // Clear the input
  event.target.value = '';
}





// Auto-sync every 5 minutes if online
setInterval(() => {
  if (isOnlineMode && userKey && db && secureSession.checkSession()) {
    syncToFirebase();
  }
}, 5 * 60 * 1000);

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  const modal = document.getElementById('firebaseModal');
  if (e.target === modal) {
    closeFirebaseModal();
  }
});

// Handle page visibility change for security
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && isOnlineMode) {
    // Page became visible, check session
    if (!secureSession.checkSession()) {
      console.log('Session expired while page was hidden');
      isOnlineMode = false;
      updateSyncStatus('Session expired', 'error');
    }
  }
});

// Handle beforeunload for cleanup
window.addEventListener('beforeunload', () => {
  // Clear sensitive session data
  secureSession.endSession();
});
// Fix 4: Add network connectivity check
function checkNetworkConnectivity() {
  return new Promise((resolve) => {
    if (!navigator.onLine) {
      resolve(false);
      return;
    }

    // Try to fetch a small resource to verify connectivity
    fetch('https://www.google.com/favicon.ico', {
      mode: 'no-cors',
      cache: 'no-cache'
    }).then(() => {
      resolve(true);
    }).catch(() => {
      resolve(false);
    });
  });
}







function loadCompletedSections() {
  const pagePath = window.location.pathname;

  document.querySelectorAll(".video-section").forEach((section) => {
    const sectionId = section.id;

    try {
      // Load completion status
      if (localStorage.getItem(`${pagePath}-${sectionId}`)) {
        updateSectionStyle(section, true);
      } else {
        updateSectionStyle(section, false);
      }

      // Load notes
      const notes = localStorage.getItem(`${pagePath}-notes-${sectionId}`);
      const notesTextArea = section.querySelector(".notes-input");
      if (notes && notesTextArea) {
        notesTextArea.value = notes;
        updateCharacterCounter(notesTextArea);
      }
    } catch (error) {
      console.warn('LocalStorage not available for loading');
      // Fallback to dataset attributes
      if (section.dataset.completed) {
        updateSectionStyle(section, true);
      }
    }
  });
}

function updateSectionStyle(section, isComplete) {
  if (isComplete) {
    section.classList.add("completed");
    const statusDot = section.querySelector(".status-dot");
    const statusText = section.querySelector(".status-text");
    if (statusDot && statusText) {
      statusDot.style.background = "var(--success-color)";
      statusText.textContent = "Completed";
    }
  } else {
    section.classList.remove("completed");
    const statusDot = section.querySelector(".status-dot");
    const statusText = section.querySelector(".status-text");
    if (statusDot && statusText) {
      statusDot.style.background = "var(--accent-color)";
      statusText.textContent = "Ready to watch";
    }
  }
}

function navigateToSection(direction, currentIndex) {
  const sections = document.querySelectorAll('.video-section');
  let targetIndex = direction === 'next' ? currentIndex + 1 : currentIndex - 1;

  if (targetIndex >= 0 && targetIndex < sections.length) {
    const headerHeight = document.querySelector('header')?.offsetHeight || 0;
    const targetSection = sections[targetIndex];
    const elementPosition = targetSection.getBoundingClientRect().top;
    const sectionHeight = targetSection.offsetHeight;
    const viewportHeight = window.innerHeight;

    // Calculate position to center the section in viewport
    const centerOffset = (viewportHeight - sectionHeight) / 2;
    const offsetPosition = elementPosition + window.pageYOffset - headerHeight - centerOffset;

    window.scrollTo({
      top: offsetPosition,
      behavior: 'smooth'
    });
  } else if (direction === 'next' && targetIndex >= sections.length) {
    // Try to navigate to next page
    const nextPageBtn = document.querySelector('.right-nav');
    if (nextPageBtn && !nextPageBtn.style.display.includes('none')) {
      nextPageBtn.click();
    } else {
      alert('You are at the last video!');
    }
  } else {
    alert('You are at the first video!');
  }
}

function navigate(targetPage) {
  // Show loading overlay
  const loadingOverlay = document.getElementById("loadingOverlay");
  if (loadingOverlay) {
    loadingOverlay.classList.add("active");
  }

  // Navigate after short delay to show loading
  setTimeout(() => {
    window.location.href = targetPage;
  }, 300);
}

// Smooth scrolling for anchor links
document.addEventListener('click', function (e) {
  if (e.target.closest('a[href^="#"]')) {
    e.preventDefault();
    const link = e.target.closest('a[href^="#"]');
    const targetId = link.getAttribute('href').slice(1);
    const targetElement = document.getElementById(targetId);

    if (targetElement) {
      const headerHeight = document.querySelector('header')?.offsetHeight || 0;
      const elementPosition = targetElement.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - headerHeight - 20;

      window.scrollTo({
        top: offsetPosition,
        behavior: 'smooth'
      });
    }
  }
});

// Keyboard navigation
document.addEventListener('keydown', function (e) {
  if (e.ctrlKey || e.metaKey) {
    switch (e.key) {
      case 'ArrowLeft':
        e.preventDefault();
        document.querySelector('.left-nav')?.click();
        break;
      case 'ArrowRight':
        e.preventDefault();
        document.querySelector('.right-nav')?.click();
        break;
      case 's':
        e.preventDefault();
        document.getElementById('exportButton')?.click();
        break;
    }
  }
});

// Notes Tools Functionality
function setupNotesTools() {
  document.querySelectorAll('.notes-container').forEach(container => {
    const notesInput = container.querySelector('.notes-input');
    const boldBtn = container.querySelector('[id^="bold-"]');
    const italicBtn = container.querySelector('[id^="italic-"]');
    const clearBtn = container.querySelector('[id^="clear-"]');
    
    if (clearBtn && notesInput) {
      clearBtn.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all notes for this video?')) {
          notesInput.value = '';
          updateCharacterCounter(notesInput);

          // Remove from localStorage
          const section = notesInput.closest('.video-section');
          const pagePath = window.location.pathname;
          try {
            localStorage.removeItem(`${pagePath}-notes-${section.id}`);
          } catch (error) {
            console.warn('LocalStorage not available');
          }

          notesInput.focus();
        }
      });
    }
  });
}


function getTutorialNameFromPath() {
  const fullPath = window.location.pathname;
  // Extract tutorial name from path like "/Security_Operations_-SOC-_101/s1.html" 
  // or "https://BrahimSAA.github.io/Python_101_for_Hackers/index.html"
  
  let tutorialName = '';
  
  if (fullPath.includes('/')) {
    const pathParts = fullPath.split('/').filter(part => part.length > 0);
    // Get the first meaningful part (tutorial folder name)
    tutorialName = pathParts[0] || 'default_tutorial';
  } else {
    tutorialName = 'default_tutorial';
  }
  
  // Clean the tutorial name to be Firebase-safe
  tutorialName = tutorialName
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
    
  console.log('Tutorial name from path:', tutorialName);
  return tutorialName || 'default_tutorial';
}

function createSafeCollectionName(accessKey) {
  // Firebase collection names have restrictions, so we'll create a safe version
  // while keeping it recognizable
  return accessKey
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .substring(0, 100); // Limit length
}

async function listUserTutorials() {
  if (!db || !userKey || !firebaseInitialized) {
    console.log('Cannot list tutorials: missing requirements');
    return [];
  }

  try {
    const collectionName = createSafeCollectionName(userKey);
    const snapshot = await db.collection(collectionName).get();
    
    const tutorials = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      tutorials.push({
        id: doc.id,
        tutorialName: data.tutorialName,
        originalPath: data.originalPath,
        fullUrl: data.fullUrl,
        lastUpdated: data.lastUpdated,
        createdAt: data.createdAt
      });
    });
    
    console.log('User tutorials:', tutorials);
    return tutorials;
  } catch (error) {
    console.error('Error listing tutorials:', error);
    return [];
  }
}

function debugFirebaseStructure() {
  const tutorialName = getTutorialNameFromPath();
  const collectionName = createSafeCollectionName(userKey);
  
  console.log('=== Firebase Structure Debug ===');
  console.log('Access Key:', userKey);
  console.log('Collection Name:', collectionName);
  console.log('Tutorial Name (Document):', tutorialName);
  console.log('Current Path:', window.location.pathname);
  console.log('Full URL:', window.location.href);
  console.log('================================');
  
  return {
    accessKey: userKey,
    collectionName: collectionName,
    documentName: tutorialName,
    path: window.location.pathname,
    url: window.location.href
  };
}
