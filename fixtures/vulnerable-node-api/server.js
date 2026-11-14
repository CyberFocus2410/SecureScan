const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/tools/ping', (req, res) => {
  const host = req.query.host;
  // Intentional OS Command Injection flaw
  exec("ping -c 1 " + host, (err, stdout, stderr) => {
    res.json({ output: stdout });
  });
});

module.exports = app;

