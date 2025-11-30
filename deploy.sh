"""
NEXUS GUARD - Complete Deployment Guide
Step-by-step guide to deploy the enterprise cybersecurity platform
"""

#!/bin/bash
# NEXUS GUARD - Complete Deployment Script
# This script sets up the entire NEXUS GUARD platform from scratch

set -e  # Exit on any error

echo "🛡️  NEXUS GUARD - Enterprise Cybersecurity Platform"
echo "======================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3.8+ first."
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    print_success "Python $python_version detected"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    docker_version=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
    print_success "Docker $docker_version detected"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "All prerequisites satisfied"
}

# Create project structure
create_project_structure() {
    print_status "Creating project structure..."
    
    # Create directories
    directories=(
        "nexus_guard"
        "nexus_guard/models"
        "nexus_guard/logs"
        "nexus_guard/data"
        "nexus_guard/certificates"
        "nexus_guard/config"
        "nexus_guard/scripts"
        "nexus_guard/security"
        "nexus_guard/monitoring"
        "nexus_guard/tests"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    print_success "Project structure created"
}

# Setup Python environment
setup_python_environment() {
    print_status "Setting up Python environment..."
    
    cd nexus_guard
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
    
    cd ..
}

# Create configuration files
create_configurations() {
    print_status "Creating configuration files..."
    
    cd nexus_guard
    
    # Run the setup script
    if [ -f "setup.py" ]; then
        python setup.py
        print_success "Configuration files created"
    else
        print_error "setup.py not found"
        exit 1
    fi
    
    cd ..
}

# Setup Docker environment
setup_docker_environment() {
    print_status "Setting up Docker environment..."
    
    cd nexus_guard
    
    # Create production docker-compose file if not exists
    if [ ! -f "docker-compose.yml" ]; then
        print_warning "docker-compose.yml not found. Creating basic configuration..."
        
        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  nexus-guard-api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DEBUG=false
      - DEPLOYMENT_MODE=PRODUCTION
    volumes:
      - ./models:/app/models
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - nexus-network

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: nexus_guard
      POSTGRES_USER: nexus_user
      POSTGRES_PASSWORD: secure_password_change_me
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - nexus-network

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - nexus-network

  mongodb:
    image: mongodb:7
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: secure_password_change_me
    volumes:
      - mongodb_data:/data/db
    restart: unless-stopped
    networks:
      - nexus-network

volumes:
  postgres_data:
  redis_data:
  mongodb_data:

networks:
  nexus-network:
    driver: bridge
EOF
        print_success "Basic Docker Compose configuration created"
    fi
    
    cd ..
}

# Initialize databases
initialize_databases() {
    print_status "Initializing databases..."
    
    cd nexus_guard
    
    # Start database services
    docker-compose up -d postgres redis mongodb
    
    print_status "Waiting for databases to be ready..."
    sleep 30
    
    # Initialize PostgreSQL database
    if [ -f "scripts/init_database.sql" ]; then
        print_status "Initializing PostgreSQL database..."
        docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE nexus_guard;" || true
        docker-compose exec -T postgres psql -U postgres -c "CREATE USER nexus_user WITH ENCRYPTED PASSWORD 'secure_password_change_me';" || true
        docker-compose exec -T postgres psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE nexus_guard TO nexus_user;" || true
        print_success "PostgreSQL database initialized"
    fi
    
    cd ..
}

# Build and start services
build_and_start_services() {
    print_status "Building and starting NEXUS GUARD services..."
    
    cd nexus_guard
    
    # Build the application
    docker-compose build nexus-guard-api
    
    # Start all services
    docker-compose up -d
    
    print_status "Waiting for services to be ready..."
    sleep 60
    
    cd ..
}

# Verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Wait for API to be ready
    max_retries=30
    retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if curl -s http://localhost:8080/api/v2/system/health > /dev/null; then
            print_success "API is responding"
            break
        fi
        
        retry_count=$((retry_count + 1))
        print_status "Waiting for API... ($retry_count/$max_retries)"
        sleep 10
    done
    
    if [ $retry_count -eq $max_retries ]; then
        print_error "API did not respond within expected time"
        return 1
    fi
    
    # Run health check
    health_response=$(curl -s http://localhost:8080/api/v2/system/health)
    if echo "$health_response" | grep -q '"status":"healthy"'; then
        print_success "System health check passed"
    else
        print_warning "System health check failed"
        echo "$health_response"
    fi
}

# Run tests
run_tests() {
    print_status "Running test suite..."
    
    cd nexus_guard
    
    if [ -f "test_suite.py" ]; then
        python test_suite.py --url http://localhost:8080 --verbose
        print_success "Test suite completed"
    else
        print_warning "Test suite not found, skipping tests"
    fi
    
    cd ..
}

# Display post-deployment information
display_post_deployment_info() {
    print_success "🚀 NEXUS GUARD deployment completed successfully!"
    echo ""
    echo "📊 Service Information:"
    echo "   • API Documentation: http://localhost:8080/docs"
    echo "   • API Health Check: http://localhost:8080/api/v2/system/health"
    echo "   • Analytics Dashboard: http://localhost:8080/api/v2/analytics/dashboard"
    echo ""
    echo "🔧 Management Commands:"
    echo "   • View logs: docker-compose logs -f nexus-guard-api"
    echo "   • Stop services: docker-compose down"
    echo "   • Restart services: docker-compose restart"
    echo "   • Update services: docker-compose pull && docker-compose up -d"
    echo ""
    echo "📈 Monitoring:"
    echo "   • Add Grafana for advanced monitoring"
    echo "   • Configure Prometheus for metrics"
    echo "   • Set up log aggregation"
    echo ""
    echo "⚠️  Important Security Notes:"
    echo "   1. Change default passwords in docker-compose.yml"
    echo "   2. Update API keys in .env file"
    echo "   3. Configure SSL/TLS certificates for production"
    echo "   4. Review and apply security hardening"
    echo "   5. Set up proper backup procedures"
    echo ""
    echo "🔒 Next Steps:"
    echo "   1. Configure threat intelligence feeds"
    echo "   2. Set up federated learning network"
    echo "   3. Integrate with existing SIEM systems"
    echo "   4. Configure compliance reporting"
    echo "   5. Set up monitoring and alerting"
    echo ""
}

# Main deployment function
main() {
    echo ""
    print_status "Starting NEXUS GUARD deployment..."
    echo ""
    
    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Consider running as a regular user for security."
    fi
    
    # Run deployment steps
    check_prerequisites
    create_project_structure
    setup_python_environment
    create_configurations
    setup_docker_environment
    initialize_databases
    build_and_start_services
    verify_deployment
    
    # Optionally run tests (can be time-consuming)
    read -p "Do you want to run the test suite? (y/N): " run_tests_choice
    if [[ $run_tests_choice =~ ^[Yy]$ ]]; then
        run_tests
    fi
    
    display_post_deployment_info
    
    print_success "Deployment completed successfully! 🎉"
}

# Handle interrupts
trap 'print_error "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"