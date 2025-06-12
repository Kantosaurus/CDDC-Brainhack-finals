const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const { spawn } = require('child_process');
const app = express();
const PORT = 4000;

app.use(cors());
app.use(bodyParser.json());

// Serve static files from the React app
app.use(express.static(path.join(__dirname, './build')));

app.post('/api/verify-and-execute', (req, res) => {
  const { moves } = req.body;

  console.log("[+] Moves received:", moves);

  const pythonProcess = spawn('/usr/bin/python3', ['./chess_executor.py', JSON.stringify(moves)]);

  let outputData = '';
  let errorData = '';

  pythonProcess.stdout.on('data', (data) => {
    console.log(`[-] STDOUT: ${data}`);
    outputData += data;
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`[-] STDERR: ${data}`);
    errorData += data;
  });

  pythonProcess.on('close', (code) => {
    console.log(`[+] Process exited with code ${code}`);

    if (errorData.length > 0) {
      return res.status(500).json({
        status: "error",
        message: errorData.toString()
      });
    }

    try {
      const result = JSON.parse(outputData.toString());
      res.json(result);
    } catch (error) {
      res.status(500).json({
        status: "error",
        message: "JSON Parse Error",
        detail: error.message,
        rawOutput: outputData.toString('utf-8')
      });
    }
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, './build', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[+]  Server running on http://0.0.0.0:${PORT}`);
});

