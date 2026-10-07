"""First-name gazetteers: a known first name followed by a surname-like word is a person candidate."""
import re

FIRST_HE = """אברהם יצחק יעקב משה אהרון דוד שלמה יוסף יוסי בנימין שמעון ראובן לוי יהודה דניאל מיכאל גבריאל רפאל
אליהו אלי אליעזר שמואל נתן נחום מנחם מרדכי חיים יחזקאל ישעיהו ירמיהו עמוס יואל יונתן יהונתן אבי אביגדור
אבנר אהוד אורי אילן איתי איתן אלון אלעד אמנון אסף בועז בני גדעון דורון הראל זאב חגי טוביה יגאל יאיר יגאל יובל
יואב ירון יורם ישי כפיר מאיר מתן נדב נועם נחמן עידו עומר עוזי עופר עמית עמרי צבי צחי קובי רועי רונן שאול שגיא
שלום תומר תמיר יהונתן אביתר אלחנן אריאל אריה ברוך גלעד הלל זיו חנן יחיאל ליאור מוטי מיכה נחום עזרא פנחס ציון
שרה רבקה רחל לאה מרים חנה אסתר רות דבורה יהודית מיכל יעל תמר נועה שירה הילה ענת אורית רונית דנה מירב
טליה נטע אפרת אסנת גלית דפנה הדס ורד זהבה חגית יפית כרמית לימור מורן מאיה נגה סיגל עינת פנינה צילה קרן
רינה שולמית שושנה תהילה אביגיל אדוה איילת אילנה אלה בתיה גאולה דליה הדסה ויקטוריה זיוה חוה טובה ירדן
לילך מלכה נעמה סיון עדינה ציפורה רוני שני שרון תאיר אורנה אתי בת שבע מרגלית נורית סמדר עליזה""".split()
FIRST_EN = """Abraham Isaac Jacob Moses Aaron David Solomon Joseph Benjamin Daniel Michael Gabriel Raphael Eli Samuel
Nathan Jonathan Yonatan Yoni Avi Avraham Yosef Yossi Moshe Uri Ilan Itai Itay Eitan Alon Elad Amnon Assaf Boaz Gideon
Doron Harel Hagai Yigal Yair Yuval Yoav Yaron Yoram Yishai Kfir Meir Matan Nadav Noam Ido Omer Uzi Ofer Amit Omri Tzvi
Roi Ronen Shaul Sagi Shalom Tomer Tamir Ariel Gilad Hillel Liran Lior Micha Eran Erez Oren Ofir Guy Nir Ran Yaniv
Sarah Rebecca Rachel Leah Miriam Hannah Esther Ruth Deborah Judith Michal Yael Tamar Noa Shira Hila Anat Orit Ronit
Dana Merav Talia Neta Efrat Osnat Galit Dafna Hadas Vered Hagit Yafit Limor Moran Maya Noga Sigal Einat Keren Rina
Shulamit Tehila Avigail Adva Ayelet Ilana Ella Batya Dalia Hadassah Yarden Lilach Naama Sivan Shani Sharon Orna Nurit
John James Robert William David Richard Thomas Charles Christopher Mark Paul Steven Andrew Kenneth Joshua Kevin Brian
George Edward Peter Mary Patricia Jennifer Linda Elizabeth Barbara Susan Jessica Karen Nancy Lisa Betty Margaret
Sandra Ashley Emily Donna Michelle Carol Amanda Melissa Laura Anna Emma Olivia Sophia""".split()
# ordinary Hebrew words that are also first names: only trusted when the full name repeats in the document
AMBIGUOUS_HE = set("""דן גל טל שי אור חן רון גיל עדי שחר ים נוי הדר אביב שקד שלום ברק אלון ארז דור עוז אמיר שמחה מזל
יפה טובה נחמה פז זיו רז ניר אושר אורן כרמל ורד קרן נגה מלכה ציון גאולה ירדן לוי יהודה ישי תאיר רוני""".split())

_HE_RE = "|".join(sorted(set(FIRST_HE), key=len, reverse=True))
_EN_RE = "|".join(sorted(set(FIRST_EN), key=len, reverse=True))
GAZ_HE = re.compile(rf"(?<![א-ת])[והלשבמכ]?(?P<f>{_HE_RE})[ ]+(?P<l>(?:(?:בן|בר)[ -])?[א-ת]{{2,}}(?:-[א-ת]{{2,}})?)(?![א-ת])")
GAZ_EN = re.compile(rf"\b(?P<f>{_EN_RE})[ ]+(?P<l>[A-Z][a-z'\-]{{1,20}})\b")
