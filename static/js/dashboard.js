function captureDashboard() {
    const dashboard = document.getElementById("dashboard-content");

    html2canvas(dashboard).then(canvas => {
        const link = document.createElement("a");
        link.download = "dashboard.png";
        link.href = canvas.toDataURL("image/png");
        link.click();
    });
}