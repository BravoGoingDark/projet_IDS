# 🛡️ IDS Monitoring Dashboard - Enhanced Version

## Overview

This is an enhanced Intrusion Detection System (IDS) monitoring dashboard with modern UI/UX design and comprehensive server monitoring capabilities. The system uses machine learning to detect network intrusions and provides real-time visualization of security events and system performance.

## ✨ Key Improvements Made

### 🎨 Modern UI/UX Design
- **Dark Theme**: Professional dark theme with gradient backgrounds and smooth animations
- **Responsive Design**: Fully responsive layout that works on desktop, tablet, and mobile devices
- **Modern Typography**: Inter font family for clean, professional appearance
- **Interactive Elements**: Hover effects, smooth transitions, and micro-interactions
- **Status Indicators**: Real-time status indicators with blinking animations
- **Card-based Layout**: Clean card design with gradient borders and shadows

### 📊 Enhanced Monitoring & Analytics
- **Real-time System Monitoring**: CPU, Memory, and Disk usage tracking
- **Server Uptime Tracking**: Continuous operation monitoring
- **Predictions Per Minute**: Real-time throughput metrics
- **Multiple Chart Types**: 
  - Traffic Distribution (Doughnut Chart)
  - Traffic Timeline (Line Chart)
  - System Resource Monitoring (Multi-line Chart)
  - Attack Analysis by Protocol (Bar Chart)

### 🔧 Technical Improvements
- **Fixed Encoding Issues**: Proper label encoder handling for categorical features
- **Enhanced Error Handling**: Robust error handling for unseen categorical values
- **CORS Support**: Cross-origin resource sharing for API access
- **WebSocket Integration**: Real-time data streaming with Socket.IO
- **Background Monitoring**: Threaded system monitoring for continuous data collection
- **API Endpoints**: RESTful API for stats, predictions, and analysis

### 🚀 New Features
- **System Resource Monitoring**: Real-time CPU, memory, and disk usage
- **Attack Pattern Analysis**: Protocol and service-based attack distribution
- **Historical Data**: Time-series data storage and visualization
- **Real-time Notifications**: Live updates via WebSocket connections
- **Comprehensive Logging**: Detailed activity logs with timestamps
- **Performance Metrics**: Throughput and accuracy measurements

## 🏗️ Architecture

### Backend (Flask)
- **app.py**: Main Flask application with enhanced monitoring
- **Model Integration**: Scikit-learn model with proper preprocessing
- **Real-time Monitoring**: Background thread for system metrics
- **API Endpoints**: RESTful endpoints for data access
- **WebSocket Support**: Real-time communication with frontend

### Frontend (HTML/CSS/JavaScript)
- **Modern CSS**: CSS Grid, Flexbox, and CSS custom properties
- **Chart.js Integration**: Multiple chart types for data visualization
- **Socket.IO Client**: Real-time data updates
- **Responsive Design**: Mobile-first responsive layout
- **Progressive Enhancement**: Graceful degradation for older browsers

### Data Processing
- **Label Encoders**: Proper handling of categorical features
- **Feature Engineering**: 41-feature vector processing
- **Real-time Prediction**: Live classification of network traffic
- **Data Storage**: In-memory storage for recent predictions and metrics

## 📋 Installation & Setup

### Prerequisites
```bash
Python 3.11+
pip (Python package manager)
```

### Installation
```bash
# Clone or extract the project
cd projet_ids

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 app.py
```

### Dependencies
- **flask**: Web framework
- **flask-socketio**: WebSocket support
- **flask-cors**: Cross-origin resource sharing
- **joblib**: Model serialization
- **pandas**: Data manipulation
- **scikit-learn**: Machine learning
- **psutil**: System monitoring

## 🚀 Usage

### Starting the Application
```bash
python3 app.py
```

The application will start on `http://localhost:5000` with the following features:
- Real-time dashboard at `/`
- API endpoints for data access
- WebSocket connections for live updates

### API Endpoints

#### GET /api/stats
Returns comprehensive system and prediction statistics:
```json
{
  "system": {
    "cpu_usage": 25.3,
    "memory_usage": 45.2,
    "disk_usage": 18.7,
    "uptime": 3600
  },
  "predictions": {
    "total": 1250,
    "attacks": 187,
    "normal": 1063,
    "attack_rate": 14.96
  }
}
```

#### GET /api/recent-predictions
Returns recent predictions with optional filtering:
- `?limit=50` - Limit number of results
- `?type=attaque` - Filter by prediction type

#### GET /api/attack-analysis
Returns attack pattern analysis:
```json
{
  "total_attacks": 187,
  "protocol_distribution": {"tcp": 120, "udp": 45, "icmp": 22},
  "service_distribution": {"http": 89, "ftp": 34, "smtp": 28},
  "most_targeted_protocol": ["tcp", 120]
}
```

#### POST /predict
Submit network traffic for classification:
```json
{
  "feature_1": "tcp",
  "feature_2": "http",
  "feature_3": "SF",
  "feature_4": 100,
  ...
}
```

## 🎯 Features

### Dashboard Components

1. **Statistics Cards**
   - Normal Traffic Count
   - Detected Attacks Count
   - Detection Rate Percentage
   - Predictions Per Minute
   - CPU Usage
   - Memory Usage
   - Disk Usage
   - System Uptime

2. **Visualization Charts**
   - **Traffic Distribution**: Pie chart showing normal vs attack traffic
   - **Traffic Timeline**: Line chart showing traffic over time
   - **System Monitoring**: Multi-line chart for resource usage
   - **Attack Analysis**: Bar chart showing attack distribution by protocol

3. **Activity Log**
   - Real-time network activity feed
   - Color-coded entries (green for normal, red for attacks)
   - Timestamp and protocol information
   - Scrollable with custom styling

### Real-time Features
- Live system metrics updates every minute
- Real-time prediction streaming via WebSocket
- Automatic chart updates with new data
- Background system monitoring
- Responsive UI updates

## 🔒 Security Features

### Intrusion Detection
- Machine learning-based classification
- 41-feature network traffic analysis
- Real-time threat detection
- Protocol-based attack analysis

### Monitoring Capabilities
- Continuous system resource monitoring
- Attack pattern recognition
- Historical data analysis
- Performance metrics tracking

## 🎨 Design System

### Color Palette
- **Primary**: #6366f1 (Indigo)
- **Secondary**: #8b5cf6 (Purple)
- **Success**: #10b981 (Green)
- **Danger**: #ef4444 (Red)
- **Warning**: #f59e0b (Amber)
- **Background**: #0f172a (Dark Blue)
- **Cards**: #1e293b (Slate)

### Typography
- **Primary Font**: Inter (Google Fonts)
- **Monospace**: JetBrains Mono (for logs and code)
- **Weights**: 300, 400, 500, 600, 700, 800, 900

### Animations
- Fade-in animations for page load
- Hover effects on interactive elements
- Smooth transitions for state changes
- Pulse animations for real-time updates
- Background gradient animations

## 📱 Responsive Design

### Breakpoints
- **Desktop**: 1200px+
- **Tablet**: 768px - 1199px
- **Mobile**: 320px - 767px

### Adaptive Features
- Flexible grid layouts
- Scalable typography
- Touch-friendly interactions
- Optimized chart sizes
- Collapsible navigation

## 🔧 Configuration

### Environment Variables
- `FLASK_ENV`: Set to 'development' for debug mode
- `SECRET_KEY`: Flask secret key for sessions

### Model Configuration
- Model file: `model/model_ids.pkl`
- Label encoders: `model/label_encoders.pkl`
- Feature count: 41 features
- Supported protocols: TCP, UDP, ICMP
- Supported services: HTTP, FTP, SMTP, DNS, etc.

## 🚀 Deployment

### Development
```bash
python3 app.py
```

### Production
For production deployment, use a WSGI server like Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker (Optional)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python3", "app.py"]
```

## 📊 Performance

### Metrics
- Real-time prediction processing
- Sub-second response times
- Efficient memory usage
- Scalable WebSocket connections
- Optimized chart rendering

### Monitoring
- System resource tracking
- Prediction throughput metrics
- Error rate monitoring
- Response time analysis

## 🛠️ Troubleshooting

### Common Issues

1. **Model Loading Error**
   - Ensure `model/model_ids.pkl` exists
   - Check scikit-learn version compatibility

2. **Encoding Errors**
   - Verify `model/label_encoders.pkl` is present
   - Check categorical feature mappings

3. **WebSocket Connection Issues**
   - Verify Socket.IO client version
   - Check CORS configuration

4. **Chart Rendering Problems**
   - Ensure Chart.js is loaded
   - Check browser console for errors

## 📈 Future Enhancements

### Planned Features
- User authentication and authorization
- Alert system with email notifications
- Advanced machine learning models
- Network topology visualization
- Historical data export
- Custom dashboard configuration
- Multi-tenant support

### Performance Improvements
- Database integration for persistent storage
- Caching layer for improved performance
- Load balancing for high availability
- Real-time streaming optimizations

## 📄 License

This project is provided as-is for educational and demonstration purposes.

## 🤝 Contributing

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For support and questions:
- Check the troubleshooting section
- Review the API documentation
- Examine the browser console for errors
- Verify all dependencies are installed

---

**Built with ❤️ using Flask, Chart.js, and modern web technologies**

