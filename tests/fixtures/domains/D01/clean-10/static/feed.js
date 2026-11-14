function render(items, el){ for (const i of items){ const li = document.createElement('li'); li.textContent = i; el.appendChild(li); } }
