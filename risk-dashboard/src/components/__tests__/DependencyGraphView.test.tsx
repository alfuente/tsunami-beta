import React from 'react';
import { render } from '@testing-library/react';
import DependencyGraphView from '../DependencyGraphView';

// Mock the API
jest.mock('../../services/api', () => ({
  dependencyApi: {
    getDomainProvidersAndServices: jest.fn().mockResolvedValue({
      providers: [],
      services: [],
      node_type: 'Domain',
      dependency_paths: { paths: [] }
    })
  }
}));

describe('DependencyGraphView', () => {
  test('renders without crashing', () => {
    const { container } = render(
      <DependencyGraphView domain="test.example.com" />
    );
    expect(container).toBeInTheDocument();
  });

  test('shows loading state initially', () => {
    const { getByRole } = render(
      <DependencyGraphView domain="test.example.com" />
    );
    expect(getByRole('progressbar')).toBeInTheDocument();
  });
});