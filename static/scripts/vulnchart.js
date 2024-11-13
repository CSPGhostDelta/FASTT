const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
const vulnerabilityData = {
    labels: ['Informational', 'Low', 'Medium', 'High', 'Critical'],
    datasets: [{
        label: 'Vulnerabilities',
        data: [5, 3, 6, 4, 2],
        backgroundColor: [
            '#36A2EB',
            '#4BC0C0', 
            '#FFCE56',
            '#FF9F40',
            '#FF6384' 
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
