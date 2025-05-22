const aiButton = document.getElementById('ai-helper-button');

// Start the AI helper and show modal
aiButton.addEventListener('click', geminiCall);

// Close the modal
document.getElementById('close-modal').addEventListener('click', () => {
    const modal = document.getElementById('ai-modal');
    modal.classList.remove("opacity-100");
    modal.classList.add("opacity-0", "pointer-events-none");

    // Enable the AI button
    aiButton.disabled = false;
    aiButton.classList.remove("bg-gray-400", "text-white", "font-semibold", "px-4", "py-2", "rounded", "opacity-50", "cursor-not-allowed");
    aiButton.classList.add("bg-green-500", "hover:bg-green-700");
});

// Animates the loading dots while waiting for a response
function animateLoadingDots(elementId, baseText = "Generating response") {
    const newText = document.getElementById(elementId);
    let dots = 0;
    const dotCycle = setInterval(() => {
        dots = (dots + 1) % 4; // cycles between number of dots
        newText.innerText = baseText + ".".repeat(dots);
    }, 500); // update every 500ms
    return dotCycle;
}

// Creates animation similar to AI typing
async function printLineEffect(elementId, text) {
    const container = document.getElementById(elementId);
    container.innerHTML = ""; // Clear's 'generating resposne' text

    const lines = text.split('\n');

    for (let line of lines) {
        const p = document.createElement("p");
        p.textContent = line;
        p.style.opacity = 0;
        p.style.transition = "opacity 1s ease";

        container.appendChild(p);

        // Trigger fade-in after a tiny pause
        requestAnimationFrame(() => {
            setTimeout(() => {
                p.style.opacity = 1;
            }, 0);
        });
    }
}

// Call the Gemini API and handle the response
async function geminiCall() {

    // Disable AI button to prevent multiple clicks
    aiButton.disabled = true; // Disable the button
    aiButton.classList.add(
        "bg-gray-400",
        "text-white",
        "opacity-50",
        "cursor-not-allowed"
    );
    aiButton.classList.remove("bg-green-500", "hover:bg-green-700");

    // Clear old response
    document.getElementById('output').value = ''
    // Start running loading animation
    const loadingDots = animateLoadingDots("output");

    try {
        const modal = document.getElementById('ai-modal');
        const output = document.getElementById('modal-title');

        // Show the modal
        modal.classList.remove("opacity-0", "pointer-events-none");
        modal.classList.add("opacity-100");

        const res = await fetch('/api/gemini', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ prompt: "What fruits and vegetables are currently in season in British Columbia? Please provide some recommendations for fresh produce. Can you keep it to a paragraph with no bullet points as this is a modal response." })
        });

        const data = await res.json();

        clearInterval(loadingDots); // Stop the loading animation
        await printLineEffect("output", data.text || "No response");

    } catch (error) {
        console.error('Error:', error);
        document.getElementById('output').innerText = 'Error contacting Gemini API';
    }
}
