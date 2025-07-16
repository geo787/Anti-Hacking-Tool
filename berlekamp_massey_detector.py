import numpy as np
from typing import List, Tuple
import logging
from datetime import datetime

class CyberAttackDetector:
    def __init__(self, sequence_length: int = 100, threshold: float = 0.8):
        self.sequence_length = sequence_length
        self.threshold = threshold
        self.network_traffic = []
        
        # Setup logging
        logging.basicConfig(
            filename=f'cyber_attack_detection_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def berlekamp_massey(self, sequence: List[int]) -> Tuple[List[int], int]:
        """
        Implements Berlekamp-Massey algorithm to find the shortest LFSR
        """
        n = len(sequence)
        c = [1]  # Connection polynomial
        b = [1]  # Previous connection polynomial
        l = 0    # Length of LFSR
        m = 1    # Number of iterations since last length change
        b.extend([0] * (n-1))
        c.extend([0] * (n-1))
        
        for i in range(n):
            d = sequence[i]
            for j in range(1, l + 1):
                d ^= c[j] & sequence[i - j]
            
            if d != 0:
                t = c[:]
                for j in range(n - i + m - 1):
                    if i - j - 1 >= 0:
                        c[i - j] ^= b[j]
                if l <= i // 2:
                    l = i + 1 - l
                    m = i + 1
                    b = t
        
        return c[:l+1], l

    def analyze_traffic(self, new_traffic_data: List[int]) -> bool:
        """
        Analyzes network traffic for potential cyber attacks
        Returns True if attack is detected, False otherwise
        """
        self.network_traffic.extend(new_traffic_data)
        
        # Keep only the most recent data points
        if len(self.network_traffic) > self.sequence_length:
            self.network_traffic = self.network_traffic[-self.sequence_length:]
            
        # Need minimum amount of data for analysis
        if len(self.network_traffic) < self.sequence_length:
            return False
            
        try:
            # Get LFSR using Berlekamp-Massey
            connection_polynomial, lfsr_length = self.berlekamp_massey(self.network_traffic)
            
            # Calculate complexity measure
            complexity_ratio = lfsr_length / len(self.network_traffic)
            
            # If sequence is too predictable (low complexity), might indicate attack
            if complexity_ratio < self.threshold:
                logging.warning(f"Potential cyber attack detected! Complexity ratio: {complexity_ratio}")
                logging.info(f"LFSR length: {lfsr_length}")
                logging.info(f"Connection polynomial: {connection_polynomial}")
                return True
                
            logging.info(f"Normal traffic pattern. Complexity ratio: {complexity_ratio}")
            return False
            
        except Exception as e:
            logging.error(f"Error during traffic analysis: {str(e)}")
            return False

    def reset(self):
        """Resets the detector state"""
        self.network_traffic = []
        logging.info("Detector state reset")

# Example usage
if __name__ == "__main__":
    detector = CyberAttackDetector(sequence_length=50, threshold=0.7)
    
    # Simulate some normal traffic (random data)
    normal_traffic = list(np.random.randint(0, 2, 40))
    result = detector.analyze_traffic(normal_traffic)
    print(f"Attack detected in normal traffic: {result}")
    
    # Simulate potential attack (repeating pattern)
    attack_traffic = [1, 0, 1, 0] * 10
    result = detector.analyze_traffic(attack_traffic)
    print(f"Attack detected in suspicious traffic: {result}")
