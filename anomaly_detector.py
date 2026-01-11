"""
Модуль для обучения модели без учителя и детекции аномалий.
"""

import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Optional
import os


class AnomalyDetector:
    """Класс для детекции аномалий в сетевом трафике."""
    
    def __init__(self, contamination: float = 0.01, score_threshold: Optional[float] = None):
        """
        Инициализация детектора аномалий.
        
        Args:
            contamination: Доля аномалий в данных (для Isolation Forest)
            score_threshold: Порог по anomaly_score (None = использовать бинарное предсказание)
                           Чем ниже порог, тем выше чувствительность
        """
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
        self.score_threshold = score_threshold
    
    def _extract_features_vector(self, aggregated_data: List[Dict]) -> np.ndarray:
        """
        Извлечение числовых признаков из агрегированных данных.
        
        Args:
            aggregated_data: Список словарей с агрегированными данными
        
        Returns:
            Массив признаков (n_samples, n_features)
        """
        if not aggregated_data:
            return np.array([]).reshape(0, 0)
        
        # Определяем имена признаков из первого элемента
        if self.feature_names is None:
            # Исключаем нечисловые и временные признаки
            exclude_keys = {'flow_key', 'src_ip', 'dst_ip', 'window_start', 
                          'window_end', 'first_seen', 'last_seen'}
            self.feature_names = [k for k in aggregated_data[0].keys() 
                                if k not in exclude_keys]
        
        # Извлекаем числовые признаки
        features = []
        for item in aggregated_data:
            feature_vector = []
            for name in self.feature_names:
                value = item.get(name, 0)
                # Преобразуем None в 0
                if value is None:
                    value = 0
                # Преобразуем в число
                try:
                    feature_vector.append(float(value))
                except (ValueError, TypeError):
                    feature_vector.append(0.0)
            features.append(feature_vector)
        
        return np.array(features)
    
    def train(self, aggregated_data: List[Dict]):
        """
        Обучение модели на агрегированных данных.
        
        Args:
            aggregated_data: Список словарей с агрегированными данными
        """
        if not aggregated_data:
            raise ValueError("Нет данных для обучения")
        
        print(f"Обучение модели на {len(aggregated_data)} образцах...")
        
        # Извлекаем признаки
        X = self._extract_features_vector(aggregated_data)
        
        if X.shape[0] == 0:
            raise ValueError("Не удалось извлечь признаки из данных")
        
        # Нормализация данных
        X_scaled = self.scaler.fit_transform(X)
        
        # Обучение модели
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print(f"Модель обучена. Использовано {X.shape[1]} признаков.")
    
    def predict(self, aggregated_data: List[Dict]) -> List[Dict]:
        """
        Предсказание аномалий в агрегированных данных.
        
        Args:
            aggregated_data: Список словарей с агрегированными данными
        
        Returns:
            Список словарей с добавленным полем 'is_anomaly' и 'anomaly_score'
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Сначала выполните train()")
        
        if not aggregated_data:
            return []
        
        # Извлекаем признаки
        X = self._extract_features_vector(aggregated_data)
        
        if X.shape[0] == 0:
            return aggregated_data
        
        # Нормализация данных
        X_scaled = self.scaler.transform(X)
        
        # Предсказание
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        # Добавляем результаты к данным
        results = []
        for i, item in enumerate(aggregated_data):
            result = item.copy()
            score = float(scores[i])
            result['anomaly_score'] = score
            
            # Определяем аномалию: либо по бинарному предсказанию, либо по порогу
            if self.score_threshold is not None:
                # Используем порог по score (для Isolation Forest: чем меньше score, тем более аномально)
                result['is_anomaly'] = score < self.score_threshold
            else:
                # Используем бинарное предсказание модели
                result['is_anomaly'] = predictions[i] == -1
            
            results.append(result)
        
        return results
    
    def save(self, filepath: str):
        """
        Сохранение модели в файл.
        
        Args:
            filepath: Путь к файлу для сохранения
        """
        if not self.is_trained:
            raise ValueError("Модель не обучена. Нечего сохранять.")
        
        data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'score_threshold': self.score_threshold
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        
        print(f"Модель сохранена в {filepath}")
    
    def load(self, filepath: str):
        """
        Загрузка модели из файла.
        
        Args:
            filepath: Путь к файлу с моделью
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл {filepath} не найден")
        
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        self.is_trained = data['is_trained']
        self.score_threshold = data.get('score_threshold', None)
        
        print(f"Модель загружена из {filepath}")
        if self.score_threshold is not None:
            print(f"Используется порог по score: {self.score_threshold}")
