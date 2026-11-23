// Hook de observação, carregado com NODE_OPTIONS=--require só no contêiner de teste.
// Grava periodicamente os caminhos dos módulos CommonJS já carregados. Não altera a aplicação.
const fs = require('fs');
function gravar() {
  try { fs.writeFileSync('/tmp/p4-modulos.txt', Object.keys(require.cache).join('\n') + '\n'); } catch (e) {}
}
setInterval(gravar, 3000).unref();
process.on('exit', gravar);
