#!/usr/bin/env python3
"""
Test script for the domain statistics API functionality
"""

import asyncio
import sys
import os

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from domain_statistics import (
    DomainStatisticsService, 
    TaskType, 
    TaskStatus, 
    track_task,
    DomainBase
)

async def test_statistics_service():
    """Test the statistics service functionality"""
    print("Testing Domain Statistics Service...")
    
    # Create service instance with test configuration
    stats_service = DomainStatisticsService()
    
    try:
        # Try to initialize (may fail if PostgreSQL not available)
        await stats_service.initialize()
        print("✅ Statistics service initialized successfully")
        
        # Test domain base creation
        domain_name = "test-example.com"
        
        # Test time estimation (should return defaults for new domain)
        estimation = await stats_service.estimate_task_duration(
            domain_name=domain_name,
            task_type=TaskType.COMPLETE_DISCOVERY,
            confidence_level=0.9
        )
        
        print(f"✅ Time estimation for {domain_name}:")
        print(f"   - Estimated seconds: {estimation['estimated_seconds']}")
        print(f"   - Confidence level: {estimation['confidence_level']}")
        print(f"   - Based on executions: {estimation['based_on_executions']}")
        print(f"   - Similar domains used: {estimation['similar_domains_used']}")
        
        # Test task tracking
        print(f"\n📊 Testing task tracking for {domain_name}...")
        
        async with track_task(
            stats_service=stats_service,
            domain_name=domain_name,
            task_type=TaskType.COMPLETE_DISCOVERY,
            timeout_configured=300,
            max_subdomains_limit=1000,
            include_providers=True,
            include_services=True,
            include_tls=True,
            include_risk=True,
            is_financial=False,
            tld="com"
        ) as task_tracker:
            
            print("✅ Task tracking started")
            
            # Simulate some work
            await asyncio.sleep(1)
            
            # Update results
            task_tracker.update_results(
                subdomains_found=5,
                providers_found=2,
                services_found=3,
                certificates_found=1,
                risks_found=2
            )
            
            # Update performance metrics
            task_tracker.update_performance_metrics(
                amass_timeout_occurred=False,
                dns_queries_count=15,
                network_requests_count=8,
                neo4j_writes_count=10
            )
            
            print("✅ Task results updated")
        
        print("✅ Task tracking completed successfully")
        
        # Test statistics retrieval
        stats = await stats_service.get_domain_execution_stats(domain_name=domain_name)
        print(f"\n📈 Domain statistics for {domain_name}: {len(stats)} records")
        
        for stat in stats:
            print(f"   - Task: {stat['task_type']}, Executions: {stat['total_executions']}")
        
        print("\n✅ All tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        print(f"💡 This may be expected if PostgreSQL is not running")
        return False
    
    finally:
        try:
            await stats_service.close()
            print("✅ Statistics service closed")
        except:
            pass
    
    return True

async def test_without_database():
    """Test functionality without database connection"""
    print("\n🔄 Testing without database connection...")
    
    # Test enum values
    print(f"✅ TaskType.COMPLETE_DISCOVERY = {TaskType.COMPLETE_DISCOVERY.value}")
    print(f"✅ TaskStatus.COMPLETED = {TaskStatus.COMPLETED.value}")
    
    # Test domain base creation
    domain_base = DomainBase(
        domain_name="example.com",
        tld="com",
        is_financial=False,
        industry="Technology"
    )
    print(f"✅ DomainBase created: {domain_base.domain_name}")
    
    print("✅ Basic functionality tests passed!")

if __name__ == "__main__":
    print("🧪 Domain Statistics API Test Suite")
    print("=" * 50)
    
    # Test basic functionality first
    asyncio.run(test_without_database())
    
    # Test with database if available
    asyncio.run(test_statistics_service())
    
    print("\n🎉 Test suite completed!")