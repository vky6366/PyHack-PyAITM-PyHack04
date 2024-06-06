document.getElementById('detectButton').addEventListener('click', async () => {
    const url = document.getElementById('url').value;
    const resultElement = document.getElementById('result');
  
    if (!url) {
      resultElement.textContent = 'Please enter a URL.';
      return;
    }
  
    try {
      const response = await fetch('http://localhost:5000/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });
  
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
  
      const result = await response.json();
      if (result.error) {
        resultElement.textContent = `Error: ${result.error}`;
      } else {
        resultElement.textContent = `Prediction: ${result.prediction}`;
      }
    } catch (error) {
      resultElement.textContent = `Error: ${error.message}`;
    }
  });
  