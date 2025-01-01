document.addEventListener('DOMContentLoaded', function() {
    fetch('/get_vulnerability_chart_data')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
            
            const vulnerabilityData = {
                labels: ['Informational', 'Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [
                        data.Informational || 0, 
                        data.Low || 0, 
                        data.Medium || 0, 
                        data.High || 0, 
                        data.Critical || 0
                    ],
                    backgroundColor: [
                        '#87CEFA',  // Informational: Light Blue
                        '#2ecc71',  // Low: Green
                        '#f39c12',  // Medium: Orange
                        '#e74c3c',  // High: Light Red
                        '#8b0000'   // Critical: Dark Red
                    ],
                    borderWidth: 0.4,
                    borderColor: "#F8F8F8"
                }]
            };

            const config = {
                type: 'doughnut',
                data: vulnerabilityData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                font: {
                                    size: 15 
                                }
                            }
                        },
                    },
                },
            };

            const vulnerabilityChart = new Chart(ctx, config);
        })
        .catch(error => {
            console.error('Error fetching vulnerability data:', error);
            // Fallback to default data if fetch fails
            const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
            
            const vulnerabilityData = {
                labels: ['Informational', 'Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#87CEFA',  // Informational: Light Blue
                        '#2ecc71',  // Low: Green
                        '#f39c12',  // Medium: Orange
                        '#e74c3c',  // High: Light Red
                        '#8b0000'   // Critical: Dark Red
                    ],
                    borderWidth: 0.4,
                    borderColor: "#F8F8F8"
                }]
            };

            const config = {
                type: 'doughnut',
                data: vulnerabilityData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                font: {
                                    size: 15 
                                }
                            }
                        },
                    },
                },
            };

            const vulnerabilityChart = new Chart(ctx, config);
        });
});