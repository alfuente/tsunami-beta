const axios = require('axios');

async function testTechnologiesAPI() {
    console.log('🧪 Testing Technologies API Endpoints...\n');
    
    const baseURL = 'http://localhost:8001';
    
    try {
        // Test 1: Basic technologies endpoint
        console.log('1. Testing /api/v1/technologies');
        const response = await axios.get(`${baseURL}/api/v1/technologies`);
        console.log(`✅ Status: ${response.status}`);
        console.log(`✅ Total technologies: ${response.data.total_count}`);
        console.log(`✅ First technology: ${response.data.technologies[0]?.name || 'None'}`);
        
        // Test 2: Technologies with filters
        console.log('\n2. Testing /api/v1/technologies with filters');
        const filteredResponse = await axios.get(`${baseURL}/api/v1/technologies`, {
            params: {
                limit: 10,
                min_usage_count: 5
            }
        });
        console.log(`✅ Filtered results: ${filteredResponse.data.technologies.length}`);
        
        // Test 3: Technology categories
        console.log('\n3. Testing /api/v1/technologies/categories');
        const categoriesResponse = await axios.get(`${baseURL}/api/v1/technologies/categories`);
        console.log(`✅ Categories count: ${categoriesResponse.data.categories.length}`);
        console.log(`✅ First category: ${categoriesResponse.data.categories[0]?.category || 'None'}`);
        
        // Test 4: Technology statistics
        console.log('\n4. Testing /api/v1/technologies/statistics');
        const statsResponse = await axios.get(`${baseURL}/api/v1/technologies/statistics`);
        console.log(`✅ Total domains: ${statsResponse.data.total_domains}`);
        console.log(`✅ Total technologies: ${statsResponse.data.total_technologies}`);
        console.log(`✅ Analysis coverage: ${statsResponse.data.analysis_coverage}%`);
        
        // Test 5: Specific technology detail
        if (response.data.technologies.length > 0) {
            const firstTech = response.data.technologies[0];
            console.log(`\n5. Testing specific technology: ${firstTech.name}`);
            const detailResponse = await axios.get(`${baseURL}/api/v1/technologies/${encodeURIComponent(firstTech.name)}`);
            console.log(`✅ Technology domains: ${detailResponse.data.domains_from_analysis?.length || 0}`);
            console.log(`✅ Scraped domains: ${detailResponse.data.domains_from_scraping?.length || 0}`);
        }
        
        console.log('\n🎉 All API tests passed successfully!');
        
    } catch (error) {
        console.error('❌ API Test Failed:', error.response?.status || error.code);
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

// Test CORS
async function testCORS() {
    console.log('\n🌐 Testing CORS headers...');
    
    try {
        const response = await axios.get('http://localhost:8001/api/v1/technologies', {
            headers: {
                'Origin': 'http://localhost:3000'
            }
        });
        
        console.log('✅ CORS test passed');
        console.log('Response headers:', {
            'access-control-allow-origin': response.headers['access-control-allow-origin'],
            'access-control-allow-methods': response.headers['access-control-allow-methods'],
            'access-control-allow-headers': response.headers['access-control-allow-headers']
        });
        
    } catch (error) {
        console.error('❌ CORS test failed:', error.message);
    }
}

testTechnologiesAPI().then(() => {
    return testCORS();
});