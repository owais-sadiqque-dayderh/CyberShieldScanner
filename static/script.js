// script.js

document.getElementById('scanButton').addEventListener('click', function() {
    const fileInput = document.getElementById('fileInput');
    if (fileInput.files.length === 0) {
      alert("Please select a file to scan.");
      return;
    }
    const file = fileInput.files[0];
    uploadFile(file);
  });
  
  document.getElementById('scanTextButton').addEventListener('click', function() {
    const text = document.getElementById('fileContent').value;
    if (text.trim() === "") {
      alert("Please paste file content to scan.");
      return;
    }
    // Create a blob from the text and construct a File object
    const blob = new Blob([text], { type: 'text/plain' });
    const file = new File([blob], "pasted_content.txt", { type: "text/plain" });
    uploadFile(file);
  });
  
  function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
  
    // Display the loading bar
    const loadingBar = document.getElementById('loadingBar');
    loadingBar.style.display = 'block';
  
    fetch('/upload', {
      method: 'POST',
      body: formData
    })
    .then(response => response.json())
    .then(data => {
      loadingBar.style.display = 'none';
      const resultDiv = document.getElementById('result');
      if (data.error) {
        resultDiv.innerHTML = "<p>Error: " + data.error + "</p>";
      } else {
        resultDiv.innerHTML = `<p>Verdict: ${data.verdict}</p>
                               <p>Risk Report: ${data.risk_report.join(', ')}</p>`;
      }
    })
    .catch(error => {
      loadingBar.style.display = 'none';
      alert("An error occurred: " + error);
    });
  }
  