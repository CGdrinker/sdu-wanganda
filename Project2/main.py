import numpy as np
from PIL import Image, ImageEnhance, ImageDraw
import matplotlib.pyplot as plt
import os
import time

# 确保中文显示正常
plt.rcParams["font.family"] = ["SimHei", "WenQuanYi Micro Hei", "Heiti TC"]


class WatermarkSystem:
    """水印系统类，实现水印的嵌入与提取功能（不依赖cv2）"""

    def __init__(self):
        """初始化水印系统"""
        self.carrier_img = None  # 载体图像(PIL Image对象)
        self.carrier_np = None  # 载体图像(numpy数组)
        self.watermark_img = None  # 水印图像(PIL Image对象)
        self.watermark_np = None  # 水印图像(numpy数组，二值化)
        self.watermarked_img = None  # 含水印图像(PIL Image对象)
        self.watermarked_np = None  # 含水印图像(numpy数组)
        self.extracted_watermark = None  # 提取的水印(numpy数组)

    def load_carrier_image(self, image_path):
        """
        加载载体图像
        :param image_path: 载体图像路径
        :return: 是否加载成功
        """
        try:
            # 打开图像并转换为RGB模式
            self.carrier_img = Image.open(image_path).convert('RGB')
            # 转换为numpy数组以便处理
            self.carrier_np = np.array(self.carrier_img)
            return True
        except Exception as e:
            print(f"加载载体图像失败: {e}")
            return False

    def load_watermark_image(self, image_path, size=None):
        """
        加载水印图像并转为二值图像
        :param image_path: 水印图像路径
        :param size: 水印尺寸，默认为None即使用原图尺寸
        :return: 是否加载成功
        """
        try:
            # 打开水印图像并转为灰度图
            self.watermark_img = Image.open(image_path).convert('L')

            # 如果指定了尺寸，则调整水印大小
            if size:
                self.watermark_img = self.watermark_img.resize(size, Image.Resampling.LANCZOS)

            # 将水印转为二值图像
            self.watermark_np = np.array(self.watermark_img)
            # 二值化处理，大于127的视为白色(255)，否则为黑色(0)
            self.watermark_np = np.where(self.watermark_np > 127, 255, 0).astype(np.uint8)
            return True
        except Exception as e:
            print(f"加载水印图像失败: {e}")
            return False

    def embed_watermark(self, bit_plane=0):
        """
        利用LSB算法嵌入水印
        :param bit_plane: 嵌入的位平面，0表示最低有效位
        :return: 是否嵌入成功
        """
        if self.carrier_np is None or self.watermark_np is None:
            print("请先加载载体图像和水印图像")
            return False

        try:
            # 确保载体图像尺寸大于等于水印图像
            if (self.carrier_np.shape[0] < self.watermark_np.shape[0] or
                    self.carrier_np.shape[1] < self.watermark_np.shape[1]):
                raise Exception("载体图像尺寸必须大于等于水印图像")

            # 创建载体图像的副本，避免修改原图
            self.watermarked_np = self.carrier_np.copy()

            # 获取水印图像的高度和宽度
            h, w = self.watermark_np.shape[:2]

            # 掩码：用于清除指定位平面的比特
            mask = ~(1 << bit_plane)
            # 水印比特的移位值
            shift = bit_plane

            # 遍历图像像素，嵌入水印
            for i in range(h):
                for j in range(w):
                    # 获取水印像素值（0或255），转为0或1
                    watermark_bit = 0 if self.watermark_np[i, j] == 0 else 1

                    # 嵌入到载体图像的指定位平面（处理RGB三个通道）
                    for c in range(3):
                        self.watermarked_np[i, j, c] = (self.carrier_np[i, j, c] & mask) | (watermark_bit << shift)

            # 将numpy数组转换回PIL Image对象
            self.watermarked_img = Image.fromarray(self.watermarked_np)
            print("水印嵌入成功")
            return True
        except Exception as e:
            print(f"水印嵌入失败: {e}")
            return False

    def extract_watermark(self, watermarked_image=None, size=None, bit_plane=0):
        """
        从含水印图像中提取水印
        :param watermarked_image: 含水印图像(numpy数组)，默认为None即使用内部存储的图像
        :param size: 水印尺寸
        :param bit_plane: 提取的位平面，0表示最低有效位
        :return: 是否提取成功
        """
        try:
            # 如果未提供含水印图像，则使用内部存储的图像
            if watermarked_image is None:
                if self.watermarked_np is None:
                    raise Exception("请先嵌入水印或提供含水印图像")
                watermarked_image = self.watermarked_np

            # 如果未指定水印尺寸，则使用原始水印尺寸
            if size is None:
                if self.watermark_np is None:
                    raise Exception("请先加载水印图像或指定水印尺寸")
                size = self.watermark_np.shape[:2]

            h, w = size
            self.extracted_watermark = np.zeros((h, w), dtype=np.uint8)

            # 提取指定位平面的比特
            shift = bit_plane

            # 遍历图像像素，提取水印
            for i in range(h):
                for j in range(w):
                    # 从第一个通道提取水印比特（这里使用R通道）
                    bit = (watermarked_image[i, j, 0] >> shift) & 1
                    self.extracted_watermark[i, j] = 255 if bit == 1 else 0

            print("水印提取成功")
            return True
        except Exception as e:
            print(f"水印提取失败: {e}")
            return False

    def save_watermarked_image(self, save_path):
        """
        保存含水印图像
        :param save_path: 保存路径
        :return: 是否保存成功
        """
        if self.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            self.watermarked_img.save(save_path)
            print(f"含水印图像已保存至: {save_path}")
            return True
        except Exception as e:
            print(f"保存含水印图像失败: {e}")
            return False

    def save_extracted_watermark(self, save_path):
        """
        保存提取的水印
        :param save_path: 保存路径
        :return: 是否保存成功
        """
        if self.extracted_watermark is None:
            print("请先提取水印")
            return False

        try:
            # 将numpy数组转换为PIL Image并保存
            Image.fromarray(self.extracted_watermark).save(save_path)
            print(f"提取的水印已保存至: {save_path}")
            return True
        except Exception as e:
            print(f"保存提取的水印失败: {e}")
            return False


class RobustnessTester:
    """水印鲁棒性测试类（不依赖cv2）"""

    def __init__(self, watermark_system):
        """
        初始化鲁棒性测试器
        :param watermark_system: WatermarkSystem实例
        """
        self.watermark_system = watermark_system
        self.attacked_images = {}  # 存储受攻击的图像(numpy数组)
        self.attacked_pil_images = {}  # 存储受攻击的图像(PIL Image)
        self.extracted_watermarks = {}  # 存储从受攻击图像中提取的水印

    def flip_horizontal(self):
        """水平翻转图像"""
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            # 使用PIL的transpose方法进行水平翻转
            attacked_pil = self.watermark_system.watermarked_img.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
            attacked_np = np.array(attacked_pil)
            self.attacked_images["水平翻转"] = attacked_np
            self.attacked_pil_images["水平翻转"] = attacked_pil
            return True
        except Exception as e:
            print(f"水平翻转失败: {e}")
            return False

    def flip_vertical(self):
        """垂直翻转图像"""
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            # 使用PIL的transpose方法进行垂直翻转
            attacked_pil = self.watermark_system.watermarked_img.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
            attacked_np = np.array(attacked_pil)
            self.attacked_images["垂直翻转"] = attacked_np
            self.attacked_pil_images["垂直翻转"] = attacked_pil
            return True
        except Exception as e:
            print(f"垂直翻转失败: {e}")
            return False

    def translate(self, dx=50, dy=50):
        """
        平移图像
        :param dx: x方向平移像素数
        :param dy: y方向平移像素数
        """
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            # 获取图像尺寸
            w, h = self.watermark_system.watermarked_img.size
            # 创建新图像，背景为白色
            attacked_pil = Image.new('RGB', (w, h), color='white')
            # 粘贴原图到新位置，实现平移
            attacked_pil.paste(self.watermark_system.watermarked_img, (dx, dy))
            attacked_np = np.array(attacked_pil)
            self.attacked_images[f"平移({dx},{dy})"] = attacked_np
            self.attacked_pil_images[f"平移({dx},{dy})"] = attacked_pil
            return True
        except Exception as e:
            print(f"图像平移失败: {e}")
            return False

    def crop(self, x=50, y=50, width=None, height=None):
        """
        截取图像
        :param x: 起始x坐标
        :param y: 起始y坐标
        :param width: 截取宽度
        :param height: 截取高度
        """
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            w, h = self.watermark_system.watermarked_img.size

            # 确定截取区域
            x2 = x + width if width else w
            y2 = y + height if height else h

            # 确保截取区域在图像范围内
            x = max(0, min(x, w))
            y = max(0, min(y, h))
            x2 = max(x + 1, min(x2, w))
            y2 = max(y + 1, min(y2, h))

            # 截取图像
            attacked_pil = self.watermark_system.watermarked_img.crop((x, y, x2, y2))
            # 调整回原始尺寸以便后续处理
            attacked_pil = attacked_pil.resize((w, h), Image.Resampling.LANCZOS)
            attacked_np = np.array(attacked_pil)
            self.attacked_images[f"截取({x},{y},{x2 - x},{y2 - y})"] = attacked_np
            self.attacked_pil_images[f"截取({x},{y},{x2 - x},{y2 - y})"] = attacked_pil
            return True
        except Exception as e:
            print(f"图像截取失败: {e}")
            return False

    def adjust_contrast(self, factor=1.5):
        """
        调整图像对比度
        :param factor: 对比度调整因子，>1增加对比度，<1降低对比度
        """
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            # 使用PIL的ImageEnhance调整对比度
            enhancer = ImageEnhance.Contrast(self.watermark_system.watermarked_img)
            attacked_pil = enhancer.enhance(factor)
            attacked_np = np.array(attacked_pil)
            self.attacked_images[f"对比度调整({factor})"] = attacked_np
            self.attacked_pil_images[f"对比度调整({factor})"] = attacked_pil
            return True
        except Exception as e:
            print(f"调整对比度失败: {e}")
            return False

    def add_noise(self, mean=0, var=0.001):
        """
        为图像添加高斯噪声
        :param mean: 噪声均值
        :param var: 噪声方差
        """
        if self.watermark_system.watermarked_np is None:
            print("请先嵌入水印")
            return False

        try:
            # 将图像转为float类型以便处理
            image = self.watermark_system.watermarked_np / 255.0
            sigma = var ** 0.5
            # 生成高斯噪声
            gauss = np.random.normal(mean, sigma, image.shape)
            # 添加噪声
            attacked = image + gauss
            # 裁剪到[0,1]范围并转换回uint8
            attacked = np.clip(attacked, 0, 1)
            attacked = (attacked * 255).astype(np.uint8)
            # 转换为PIL Image
            attacked_pil = Image.fromarray(attacked)
            self.attacked_images[f"高斯噪声(mean={mean},var={var})"] = attacked
            self.attacked_pil_images[f"高斯噪声(mean={mean},var={var})"] = attacked_pil
            return True
        except Exception as e:
            print(f"添加噪声失败: {e}")
            return False

    def rotate(self, angle=30):
        """
        旋转图像
        :param angle: 旋转角度
        """
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            # 使用PIL的rotate方法旋转图像，背景填充白色
            attacked_pil = self.watermark_system.watermarked_img.rotate(angle, expand=False, fillcolor='white')
            attacked_np = np.array(attacked_pil)
            self.attacked_images[f"旋转({angle}度)"] = attacked_np
            self.attacked_pil_images[f"旋转({angle}度)"] = attacked_pil
            return True
        except Exception as e:
            print(f"图像旋转失败: {e}")
            return False

    def scale(self, scale_factor=0.5):
        """
        缩放图像
        :param scale_factor: 缩放因子
        """
        if self.watermark_system.watermarked_img is None:
            print("请先嵌入水印")
            return False

        try:
            w, h = self.watermark_system.watermarked_img.size
            # 计算新尺寸
            new_size = (int(w * scale_factor), int(h * scale_factor))
            # 缩小图像
            attacked_pil = self.watermark_system.watermarked_img.resize(new_size, Image.Resampling.LANCZOS)
            # 恢复原始尺寸
            attacked_pil = attacked_pil.resize((w, h), Image.Resampling.LANCZOS)
            attacked_np = np.array(attacked_pil)
            self.attacked_images[f"缩放({scale_factor})"] = attacked_np
            self.attacked_pil_images[f"缩放({scale_factor})"] = attacked_pil
            return True
        except Exception as e:
            print(f"图像缩放失败: {e}")
            return False

    def extract_from_attacked(self):
        """从所有受攻击的图像中提取水印"""
        if not self.attacked_images:
            print("请先对图像进行攻击操作")
            return False

        try:
            # 获取水印尺寸
            wm_size = self.watermark_system.watermark_np.shape[:2]

            # 对每个受攻击的图像提取水印
            for name, img_np in self.attacked_images.items():
                # 创建临时的WatermarkSystem实例进行提取
                temp_ws = WatermarkSystem()
                temp_ws.extract_watermark(watermarked_image=img_np, size=wm_size)
                self.extracted_watermarks[name] = temp_ws.extracted_watermark

            print("已从所有受攻击图像中提取水印")
            return True
        except Exception as e:
            print(f"提取受攻击图像中的水印失败: {e}")
            return False

    def calculate_similarity(self, original, extracted):
        """
        计算原始水印与提取水印的相似度
        :param original: 原始水印
        :param extracted: 提取的水印
        :return: 相似度值，范围[0,1]
        """
        # 将水印转为二进制数组（0和1）
        original_bin = (original / 255).astype(np.uint8)
        extracted_bin = (extracted / 255).astype(np.uint8)

        # 计算相同像素的数量
        same = np.sum(original_bin == extracted_bin)
        # 计算总像素数量
        total = original_bin.size
        # 返回相似度
        return same / total

    def evaluate_robustness(self):
        """评估水印在各种攻击下的鲁棒性"""
        if not self.extracted_watermarks or self.watermark_system.watermark_np is None:
            print("请先提取受攻击图像中的水印")
            return None

        try:
            robustness_scores = {}
            original_watermark = self.watermark_system.watermark_np

            # 计算每个受攻击图像中提取的水印与原始水印的相似度
            for name, extracted in self.extracted_watermarks.items():
                # 确保提取的水印与原始水印尺寸相同
                if extracted.shape != original_watermark.shape:
                    # 调整提取的水印尺寸
                    extracted_pil = Image.fromarray(extracted)
                    extracted_resized = extracted_pil.resize(
                        (original_watermark.shape[1], original_watermark.shape[0]),
                        Image.Resampling.LANCZOS
                    )
                    extracted_resized_np = np.array(extracted_resized)
                    similarity = self.calculate_similarity(original_watermark, extracted_resized_np)
                else:
                    similarity = self.calculate_similarity(original_watermark, extracted)

                robustness_scores[name] = similarity

            return robustness_scores
        except Exception as e:
            print(f"评估鲁棒性失败: {e}")
            return None

    def visualize_results(self, save_dir=None):
        """
        可视化实验结果
        :param save_dir: 保存结果的目录，为None则不保存
        """
        # 创建结果可视化
        fig = plt.figure(figsize=(15, 10))
        fig.suptitle("水印嵌入与鲁棒性测试结果", fontsize=16)

        # 原始载体图像
        ax1 = fig.add_subplot(2, 3, 1)
        ax1.imshow(self.watermark_system.carrier_img)
        ax1.set_title("原始载体图像")
        ax1.axis('off')

        # 原始水印
        ax2 = fig.add_subplot(2, 3, 2)
        ax2.imshow(self.watermark_system.watermark_np, cmap='gray')
        ax2.set_title("原始水印")
        ax2.axis('off')

        # 含水印图像
        ax3 = fig.add_subplot(2, 3, 3)
        ax3.imshow(self.watermark_system.watermarked_img)
        ax3.set_title("含水印图像")
        ax3.axis('off')

        # 从原始含水印图像提取的水印
        ax4 = fig.add_subplot(2, 3, 4)
        ax4.imshow(self.watermark_system.extracted_watermark, cmap='gray')
        ax4.set_title("提取的水印(无攻击)")
        ax4.axis('off')

        # 显示两个攻击示例及其提取的水印
        attack_names = list(self.attacked_images.keys())[:2]

        if attack_names:
            # 第一个攻击示例
            ax5 = fig.add_subplot(2, 3, 5)
            ax5.imshow(self.attacked_pil_images[attack_names[0]])
            ax5.set_title(f"{attack_names[0]}")
            ax5.axis('off')

            # 从第一个攻击图像提取的水印
            ax6 = fig.add_subplot(2, 3, 6)
            ax6.imshow(self.extracted_watermarks[attack_names[0]], cmap='gray')
            ax6.set_title(f"提取的水印({attack_names[0]})")
            ax6.axis('off')

        plt.tight_layout(rect=[0, 0, 1, 0.96])

        # 如果指定了保存目录，则保存图像
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, "watermark_results.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"结果图像已保存至: {save_path}")

        plt.show()

        # 显示鲁棒性评分
        robustness_scores = self.evaluate_robustness()
        if robustness_scores:
            print("\n鲁棒性测试结果（相似度越高鲁棒性越好）:")
            for name, score in robustness_scores.items():
                print(f"{name}: {score:.4f}")

            # 绘制鲁棒性评分条形图
            plt.figure(figsize=(12, 6))
            plt.bar(robustness_scores.keys(), robustness_scores.values(), color='skyblue')
            plt.title("不同攻击下的水印提取相似度")
            plt.ylabel("相似度")
            plt.ylim(0, 1.0)
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()

            if save_dir:
                save_path = os.path.join(save_dir, "robustness_scores.png")
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                print(f"鲁棒性评分图已保存至: {save_path}")

            plt.show()


def create_test_images(carrier_path, watermark_path):
    """创建测试用的载体图像和水印图像"""
    # 创建载体图像
    carrier = Image.new('RGB', (512, 512), color=(200, 200, 200))
    draw = ImageDraw.Draw(carrier)
    draw.rectangle([(100, 100), (400, 400)], fill=(100, 150, 200))
    carrier.save(carrier_path)

    # 创建水印图像
    watermark = Image.new('L', (128, 128), color=0)
    draw = ImageDraw.Draw(watermark)
    draw.rectangle([(30, 30), (100, 100)], fill=255)
    draw.ellipse([(50, 50), (80, 80)], fill=0)
    watermark.save(watermark_path)


def main():
    """主函数，演示水印嵌入、提取和鲁棒性测试的完整流程"""
    # 创建水印系统实例
    ws = WatermarkSystem()

    # 加载载体图像和水印图像
    carrier_path = "carrier.jpg"  # 载体图像
    watermark_path = "watermark.png"  # 水印图像

    # 如果示例图像不存在，则创建简单的测试图像
    if not os.path.exists(carrier_path) or not os.path.exists(watermark_path):
        print("创建测试图像...")
        create_test_images(carrier_path, watermark_path)

    # 加载图像
    ws.load_carrier_image(carrier_path)
    # 调整水印大小为载体图像的1/4
    carrier_w, carrier_h = ws.carrier_img.size
    ws.load_watermark_image(watermark_path, size=(carrier_h // 4, carrier_w // 4))

    # 嵌入水印
    start_time = time.time()
    ws.embed_watermark(bit_plane=0)  # 使用最低有效位
    embed_time = time.time() - start_time
    print(f"水印嵌入耗时: {embed_time:.4f}秒")

    # 从原始含水印图像中提取水印
    start_time = time.time()
    ws.extract_watermark()
    extract_time = time.time() - start_time
    print(f"水印提取耗时: {extract_time:.4f}秒")

    # 创建鲁棒性测试器
    tester = RobustnessTester(ws)

    # 进行各种攻击
    tester.flip_horizontal()
    tester.flip_vertical()
    tester.translate(dx=30, dy=20)
    tester.crop(x=50, y=50, width=carrier_w - 100, height=carrier_h - 100)
    tester.adjust_contrast(factor=2.0)
    tester.adjust_contrast(factor=0.5)
    tester.add_noise(var=0.002)
    tester.rotate(angle=15)
    tester.scale(scale_factor=0.7)

    # 从受攻击的图像中提取水印
    tester.extract_from_attacked()

    # 可视化结果
    result_dir = "watermark_results_pillow"
    tester.visualize_results(save_dir=result_dir)

    # 保存结果图像
    ws.save_watermarked_image(os.path.join(result_dir, "watermarked_image.jpg"))
    ws.save_extracted_watermark(os.path.join(result_dir, "extracted_watermark.png"))

    # 保存所有受攻击的图像和从中提取的水印
    for name, img in tester.attacked_pil_images.items():
        safe_name = name.replace("(", "_").replace(")", "_").replace(",", "_").replace(":", "_")
        img.save(os.path.join(result_dir, f"attacked_{safe_name}.jpg"))

    for name, wm in tester.extracted_watermarks.items():
        safe_name = name.replace("(", "_").replace(")", "_").replace(",", "_").replace(":", "_")
        Image.fromarray(wm).save(os.path.join(result_dir, f"extracted_{safe_name}.png"))


if __name__ == "__main__":
    main()
