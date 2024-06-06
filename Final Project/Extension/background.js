chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ serverStarted: false });
  });
  
  chrome.browserAction.onClicked.addListener(() => {
    chrome.storage.local.get('serverStarted', (data) => {
      if (!data.serverStarted) {
        fetch('http://localhost:5000/predict', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ url: 'test' })
        })
        .then(response => {
          if (response.ok) {
            chrome.storage.local.set({ serverStarted: true });
          }
        })
        .catch(error => console.error('Error:', error));
      }
    });
  });
  