PGDMP                       }            lms    16.4    16.4 V    W           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            X           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            Y           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            Z           1262    16397    lms    DATABASE     ~   CREATE DATABASE lms WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE lms;
                postgres    false            �            1259    16526    admins    TABLE     3  CREATE TABLE public.admins (
    id integer NOT NULL,
    fullname character varying(255) NOT NULL,
    username character varying(255) NOT NULL,
    password character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.admins;
       public         heap    postgres    false            �            1259    16532    admins_id_seq    SEQUENCE     �   CREATE SEQUENCE public.admins_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.admins_id_seq;
       public          postgres    false    224            [           0    0    admins_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.admins_id_seq OWNED BY public.admins.id;
          public          postgres    false    225            �            1259    16428 
   enrollment    TABLE     `   CREATE TABLE public.enrollment (
    id_kelas integer NOT NULL,
    id_user integer NOT NULL
);
    DROP TABLE public.enrollment;
       public         heap    postgres    false            �            1259    16533    jawaban    TABLE     �   CREATE TABLE public.jawaban (
    id_jawaban integer NOT NULL,
    id_user integer NOT NULL,
    id_soal integer NOT NULL,
    jawaban text,
    nilai character(1),
    waktu_submit timestamp without time zone
);
    DROP TABLE public.jawaban;
       public         heap    postgres    false            �            1259    16538    jawaban_id_jawaban_seq    SEQUENCE     �   CREATE SEQUENCE public.jawaban_id_jawaban_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.jawaban_id_jawaban_seq;
       public          postgres    false    226            \           0    0    jawaban_id_jawaban_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.jawaban_id_jawaban_seq OWNED BY public.jawaban.id_jawaban;
          public          postgres    false    227            �            1259    16413 
   kelas_ajar    TABLE     �   CREATE TABLE public.kelas_ajar (
    nama_mapel character(255) NOT NULL,
    kelas character(5) NOT NULL,
    id_kelas integer NOT NULL,
    token character(20) NOT NULL
);
    DROP TABLE public.kelas_ajar;
       public         heap    postgres    false            �            1259    16473    kelas_ajar_id_kelas_seq    SEQUENCE     �   CREATE SEQUENCE public.kelas_ajar_id_kelas_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.kelas_ajar_id_kelas_seq;
       public          postgres    false    217            ]           0    0    kelas_ajar_id_kelas_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.kelas_ajar_id_kelas_seq OWNED BY public.kelas_ajar.id_kelas;
          public          postgres    false    219            �            1259    16486    kuis    TABLE     �   CREATE TABLE public.kuis (
    id_kuis integer NOT NULL,
    id_kelas integer NOT NULL,
    judul_kuis character(255) NOT NULL,
    batas_waktu timestamp with time zone
);
    DROP TABLE public.kuis;
       public         heap    postgres    false            �            1259    16485    kuis_id_kuis_seq    SEQUENCE     �   CREATE SEQUENCE public.kuis_id_kuis_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.kuis_id_kuis_seq;
       public          postgres    false    221            ^           0    0    kuis_id_kuis_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.kuis_id_kuis_seq OWNED BY public.kuis.id_kuis;
          public          postgres    false    220            �            1259    24715    materi    TABLE     �   CREATE TABLE public.materi (
    id_materi integer NOT NULL,
    id_kelas integer NOT NULL,
    nama_materi character varying(255) NOT NULL,
    file_materi character varying(255) NOT NULL
);
    DROP TABLE public.materi;
       public         heap    postgres    false            �            1259    24720    materi_id_materi_seq    SEQUENCE     �   CREATE SEQUENCE public.materi_id_materi_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE public.materi_id_materi_seq;
       public          postgres    false    228            _           0    0    materi_id_materi_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE public.materi_id_materi_seq OWNED BY public.materi.id_materi;
          public          postgres    false    229            �            1259    24771 
   pengumuman    TABLE     �   CREATE TABLE public.pengumuman (
    id_pengumuman integer NOT NULL,
    id_kelas integer NOT NULL,
    judul character(255) NOT NULL,
    konten text NOT NULL,
    tanggal_dibuat timestamp with time zone NOT NULL
);
    DROP TABLE public.pengumuman;
       public         heap    postgres    false            �            1259    24770    pengumuman_id_pengumuman_seq    SEQUENCE     �   CREATE SEQUENCE public.pengumuman_id_pengumuman_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 3   DROP SEQUENCE public.pengumuman_id_pengumuman_seq;
       public          postgres    false    233            `           0    0    pengumuman_id_pengumuman_seq    SEQUENCE OWNED BY     ]   ALTER SEQUENCE public.pengumuman_id_pengumuman_seq OWNED BY public.pengumuman.id_pengumuman;
          public          postgres    false    232            �            1259    16500    soal    TABLE     �   CREATE TABLE public.soal (
    id_soal integer NOT NULL,
    id_kuis integer NOT NULL,
    pertanyaan text NOT NULL,
    kunci_jawaban text NOT NULL
);
    DROP TABLE public.soal;
       public         heap    postgres    false            �            1259    16499    soal_id_soal_seq    SEQUENCE     �   CREATE SEQUENCE public.soal_id_soal_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.soal_id_soal_seq;
       public          postgres    false    223            a           0    0    soal_id_soal_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.soal_id_soal_seq OWNED BY public.soal.id_soal;
          public          postgres    false    222            �            1259    24721    user_scores    TABLE       CREATE TABLE public.user_scores (
    id integer NOT NULL,
    user_id integer NOT NULL,
    kuis_id integer NOT NULL,
    score character(1),
    CONSTRAINT user_scores_score_check CHECK ((score = ANY (ARRAY['A'::bpchar, 'B'::bpchar, 'C'::bpchar, 'D'::bpchar, 'E'::bpchar])))
);
    DROP TABLE public.user_scores;
       public         heap    postgres    false            �            1259    24725    user_scores_id_seq    SEQUENCE     �   CREATE SEQUENCE public.user_scores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.user_scores_id_seq;
       public          postgres    false    230            b           0    0    user_scores_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.user_scores_id_seq OWNED BY public.user_scores.id;
          public          postgres    false    231            �            1259    16398    users    TABLE     �  CREATE TABLE public.users (
    id integer NOT NULL,
    fullname character varying(100) NOT NULL,
    username character varying(50) NOT NULL,
    password text NOT NULL,
    email character varying(100) NOT NULL,
    role character varying(10) NOT NULL,
    nisn_or_nuptk character varying(50),
    is_accepted boolean DEFAULT false,
    CONSTRAINT users_check CHECK (((((role)::text = 'student'::text) AND (nisn_or_nuptk IS NOT NULL)) OR (((role)::text = 'teacher'::text) AND (nisn_or_nuptk IS NOT NULL)) OR ((role IS NULL) AND (nisn_or_nuptk IS NULL)))),
    CONSTRAINT users_role_check CHECK (((role)::text = ANY (ARRAY[('student'::character varying)::text, ('teacher'::character varying)::text])))
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16405    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    215            c           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    216            �           2604    24763 	   admins id    DEFAULT     f   ALTER TABLE ONLY public.admins ALTER COLUMN id SET DEFAULT nextval('public.admins_id_seq'::regclass);
 8   ALTER TABLE public.admins ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    225    224            �           2604    24764    jawaban id_jawaban    DEFAULT     x   ALTER TABLE ONLY public.jawaban ALTER COLUMN id_jawaban SET DEFAULT nextval('public.jawaban_id_jawaban_seq'::regclass);
 A   ALTER TABLE public.jawaban ALTER COLUMN id_jawaban DROP DEFAULT;
       public          postgres    false    227    226            ~           2604    24765    kelas_ajar id_kelas    DEFAULT     z   ALTER TABLE ONLY public.kelas_ajar ALTER COLUMN id_kelas SET DEFAULT nextval('public.kelas_ajar_id_kelas_seq'::regclass);
 B   ALTER TABLE public.kelas_ajar ALTER COLUMN id_kelas DROP DEFAULT;
       public          postgres    false    219    217                       2604    24766    kuis id_kuis    DEFAULT     l   ALTER TABLE ONLY public.kuis ALTER COLUMN id_kuis SET DEFAULT nextval('public.kuis_id_kuis_seq'::regclass);
 ;   ALTER TABLE public.kuis ALTER COLUMN id_kuis DROP DEFAULT;
       public          postgres    false    221    220    221            �           2604    24767    materi id_materi    DEFAULT     t   ALTER TABLE ONLY public.materi ALTER COLUMN id_materi SET DEFAULT nextval('public.materi_id_materi_seq'::regclass);
 ?   ALTER TABLE public.materi ALTER COLUMN id_materi DROP DEFAULT;
       public          postgres    false    229    228            �           2604    24774    pengumuman id_pengumuman    DEFAULT     �   ALTER TABLE ONLY public.pengumuman ALTER COLUMN id_pengumuman SET DEFAULT nextval('public.pengumuman_id_pengumuman_seq'::regclass);
 G   ALTER TABLE public.pengumuman ALTER COLUMN id_pengumuman DROP DEFAULT;
       public          postgres    false    232    233    233            �           2604    24768    soal id_soal    DEFAULT     l   ALTER TABLE ONLY public.soal ALTER COLUMN id_soal SET DEFAULT nextval('public.soal_id_soal_seq'::regclass);
 ;   ALTER TABLE public.soal ALTER COLUMN id_soal DROP DEFAULT;
       public          postgres    false    222    223    223            �           2604    24761    user_scores id    DEFAULT     p   ALTER TABLE ONLY public.user_scores ALTER COLUMN id SET DEFAULT nextval('public.user_scores_id_seq'::regclass);
 =   ALTER TABLE public.user_scores ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    231    230            |           2604    24769    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    215            K          0    16526    admins 
   TABLE DATA           U   COPY public.admins (id, fullname, username, password, email, created_at) FROM stdin;
    public          postgres    false    224   e       E          0    16428 
   enrollment 
   TABLE DATA           7   COPY public.enrollment (id_kelas, id_user) FROM stdin;
    public          postgres    false    218   Xe       M          0    16533    jawaban 
   TABLE DATA           ]   COPY public.jawaban (id_jawaban, id_user, id_soal, jawaban, nilai, waktu_submit) FROM stdin;
    public          postgres    false    226   �e       D          0    16413 
   kelas_ajar 
   TABLE DATA           H   COPY public.kelas_ajar (nama_mapel, kelas, id_kelas, token) FROM stdin;
    public          postgres    false    217   s       H          0    16486    kuis 
   TABLE DATA           J   COPY public.kuis (id_kuis, id_kelas, judul_kuis, batas_waktu) FROM stdin;
    public          postgres    false    221   �s       O          0    24715    materi 
   TABLE DATA           O   COPY public.materi (id_materi, id_kelas, nama_materi, file_materi) FROM stdin;
    public          postgres    false    228   �t       T          0    24771 
   pengumuman 
   TABLE DATA           \   COPY public.pengumuman (id_pengumuman, id_kelas, judul, konten, tanggal_dibuat) FROM stdin;
    public          postgres    false    233   �t       J          0    16500    soal 
   TABLE DATA           K   COPY public.soal (id_soal, id_kuis, pertanyaan, kunci_jawaban) FROM stdin;
    public          postgres    false    223   Du       Q          0    24721    user_scores 
   TABLE DATA           B   COPY public.user_scores (id, user_id, kuis_id, score) FROM stdin;
    public          postgres    false    230   �w       B          0    16398    users 
   TABLE DATA           j   COPY public.users (id, fullname, username, password, email, role, nisn_or_nuptk, is_accepted) FROM stdin;
    public          postgres    false    215   �w       d           0    0    admins_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.admins_id_seq', 1, true);
          public          postgres    false    225            e           0    0    jawaban_id_jawaban_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.jawaban_id_jawaban_seq', 88, true);
          public          postgres    false    227            f           0    0    kelas_ajar_id_kelas_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.kelas_ajar_id_kelas_seq', 22, true);
          public          postgres    false    219            g           0    0    kuis_id_kuis_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.kuis_id_kuis_seq', 42, true);
          public          postgres    false    220            h           0    0    materi_id_materi_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.materi_id_materi_seq', 8, true);
          public          postgres    false    229            i           0    0    pengumuman_id_pengumuman_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('public.pengumuman_id_pengumuman_seq', 4, true);
          public          postgres    false    232            j           0    0    soal_id_soal_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.soal_id_soal_seq', 37, true);
          public          postgres    false    222            k           0    0    user_scores_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.user_scores_id_seq', 1, false);
          public          postgres    false    231            l           0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 70, true);
          public          postgres    false    216            �           2606    16546    admins admins_email_key 
   CONSTRAINT     S   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_email_key UNIQUE (email);
 A   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_email_key;
       public            postgres    false    224            �           2606    16548    admins admins_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_pkey;
       public            postgres    false    224            �           2606    16550    admins admins_username_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_username_key UNIQUE (username);
 D   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_username_key;
       public            postgres    false    224            �           2606    16432    enrollment enrollment_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT enrollment_pkey PRIMARY KEY (id_kelas, id_user);
 D   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT enrollment_pkey;
       public            postgres    false    218    218            �           2606    16552    jawaban jawaban_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_pkey PRIMARY KEY (id_jawaban);
 >   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_pkey;
       public            postgres    false    226            �           2606    16479    kelas_ajar kelas_ajar_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.kelas_ajar
    ADD CONSTRAINT kelas_ajar_pkey PRIMARY KEY (id_kelas);
 D   ALTER TABLE ONLY public.kelas_ajar DROP CONSTRAINT kelas_ajar_pkey;
       public            postgres    false    217            �           2606    16491    kuis kuis_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT kuis_pkey PRIMARY KEY (id_kuis);
 8   ALTER TABLE ONLY public.kuis DROP CONSTRAINT kuis_pkey;
       public            postgres    false    221            �           2606    24735    materi materi_pkey 
   CONSTRAINT     W   ALTER TABLE ONLY public.materi
    ADD CONSTRAINT materi_pkey PRIMARY KEY (id_materi);
 <   ALTER TABLE ONLY public.materi DROP CONSTRAINT materi_pkey;
       public            postgres    false    228            �           2606    24776    pengumuman pengumuman_pkey 
   CONSTRAINT     c   ALTER TABLE ONLY public.pengumuman
    ADD CONSTRAINT pengumuman_pkey PRIMARY KEY (id_pengumuman);
 D   ALTER TABLE ONLY public.pengumuman DROP CONSTRAINT pengumuman_pkey;
       public            postgres    false    233            �           2606    16507    soal soal_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.soal
    ADD CONSTRAINT soal_pkey PRIMARY KEY (id_soal);
 8   ALTER TABLE ONLY public.soal DROP CONSTRAINT soal_pkey;
       public            postgres    false    223            �           2606    24737    user_scores user_scores_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.user_scores
    ADD CONSTRAINT user_scores_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.user_scores DROP CONSTRAINT user_scores_pkey;
       public            postgres    false    230            �           2606    24739 +   user_scores user_scores_user_id_kuis_id_key 
   CONSTRAINT     r   ALTER TABLE ONLY public.user_scores
    ADD CONSTRAINT user_scores_user_id_kuis_id_key UNIQUE (user_id, kuis_id);
 U   ALTER TABLE ONLY public.user_scores DROP CONSTRAINT user_scores_user_id_kuis_id_key;
       public            postgres    false    230    230            �           2606    16408    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    215            �           2606    16410    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    215            �           2606    16412    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public            postgres    false    215            �           2606    16480    enrollment id_kelas    FK CONSTRAINT     �   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas) NOT VALID;
 =   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_kelas;
       public          postgres    false    217    218    4753            �           2606    16492    kuis id_kelas    FK CONSTRAINT     x   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas);
 7   ALTER TABLE ONLY public.kuis DROP CONSTRAINT id_kelas;
       public          postgres    false    221    4753    217            �           2606    24779    pengumuman id_kelas    FK CONSTRAINT     �   ALTER TABLE ONLY public.pengumuman
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas) NOT VALID;
 =   ALTER TABLE ONLY public.pengumuman DROP CONSTRAINT id_kelas;
       public          postgres    false    4753    217    233            �           2606    16508    soal id_kuis    FK CONSTRAINT     o   ALTER TABLE ONLY public.soal
    ADD CONSTRAINT id_kuis FOREIGN KEY (id_kuis) REFERENCES public.kuis(id_kuis);
 6   ALTER TABLE ONLY public.soal DROP CONSTRAINT id_kuis;
       public          postgres    false    223    4757    221            �           2606    16438    enrollment id_user    FK CONSTRAINT     q   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_user FOREIGN KEY (id_user) REFERENCES public.users(id);
 <   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_user;
       public          postgres    false    4749    215    218            �           2606    16553    jawaban jawaban_id_soal_fkey    FK CONSTRAINT        ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_id_soal_fkey FOREIGN KEY (id_soal) REFERENCES public.soal(id_soal);
 F   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_id_soal_fkey;
       public          postgres    false    4759    223    226            �           2606    16558    jawaban jawaban_id_user_fkey    FK CONSTRAINT     {   ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_id_user_fkey FOREIGN KEY (id_user) REFERENCES public.users(id);
 F   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_id_user_fkey;
       public          postgres    false    226    4749    215            �           2606    24740    materi materi_id_kelas_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.materi
    ADD CONSTRAINT materi_id_kelas_fkey FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas) ON DELETE CASCADE;
 E   ALTER TABLE ONLY public.materi DROP CONSTRAINT materi_id_kelas_fkey;
       public          postgres    false    4753    228    217            �           2606    16563    soal soal_id_kuis_fkey    FK CONSTRAINT     y   ALTER TABLE ONLY public.soal
    ADD CONSTRAINT soal_id_kuis_fkey FOREIGN KEY (id_kuis) REFERENCES public.kuis(id_kuis);
 @   ALTER TABLE ONLY public.soal DROP CONSTRAINT soal_id_kuis_fkey;
       public          postgres    false    221    223    4757            �           2606    24745 $   user_scores user_scores_kuis_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_scores
    ADD CONSTRAINT user_scores_kuis_id_fkey FOREIGN KEY (kuis_id) REFERENCES public.kuis(id_kuis);
 N   ALTER TABLE ONLY public.user_scores DROP CONSTRAINT user_scores_kuis_id_fkey;
       public          postgres    false    221    230    4757            �           2606    24750 $   user_scores user_scores_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_scores
    ADD CONSTRAINT user_scores_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
 N   ALTER TABLE ONLY public.user_scores DROP CONSTRAINT user_scores_user_id_fkey;
       public          postgres    false    4749    215    230            K   E   x�3�LL��̃�ũ9�F��CjEbnAN�^r~.��������������������������1W� ���      E   W   x�%���0�w\���@/�_��vF����9�٭�I'�hQQ���M����
+���
+���k���k����mg?��� uYP      M   P  x��[ێ�}n�'�����O�%6�x��JM�8}���\{���KR�����/���;��&�ŪsN��:Y>M���7�������z���}!R-JYI|Ш��'Ry��(U�e�����;	�ne-�FՍ,��1O^'?����e�\�$�Z�z+|���J�T0��Uպi�g)�d��Vշ�U�s)
��;��֢���&=�U[���d���<�u�2x"��T�ph���0��jY��D����T���7�ix�T+� 70�L�>˼53ge�*X���ooa����F�d4�u<���4`��w���s�`8
��y�M��6-<�Uc'�� �Z����.���hk���������&Y.p�^���`w�T�9H�o��w���M����	���f��L�<��y�{�,�и���6��&���|���)a
x#Os��C��푙62�B4��{�6�T�����p0�>��m!1_Һ�r�YWsd���t��  L՚���g<Jjj1��y���}y0,�թ���~�F�o�H ��0B.u�>� w�������ޓ���ݨ`D���{�ȕ�u���a�d_���8HJ^�����7��8��6�_�&��F�r�`��T�)v�V���T���#v��"_���LܚL���;yp�zX���4�@|)��iP���z���x�9��q��C�����F��	�Y}��l�kރ��_}���m�����)�@���� D�Z�,�[�wEi��[9�(x��Cw��YG�w��*�(�n|�����~)�8�f�}�t�2���~��F����v�G�M��I��ZX$3��΋��d���:���o�� ���ܿN�.F��0,�؏=�&��+=�s�r"�0��b��ow��ִ$���5�����["���du9����m�	�����)����(&�qdB<-��%-����Aj5�x���r�\&��!��|j��&m$�g��I��&�O�%��)�����اAo#efA�U�s��6e����K@�	|�2d���d�����.�2Y���rS�V�e��]��*��ϸ�}���
�vW+����PW!̢|蒙��]f��}v�@~�AX�)0�j�R-w��sV;�B��	,�(���X�;�,~���xK�eg|9t�\q�����7����L���匯U���y!�"Z�q'8�	�V�N���]-Vհg�U�p����v�V�jRj1��u�^�- �rmV\'k��W�����J�B�������g"�����ARm��!wP(��5�(�F���eQ4�����op&Ћ�I��u<�|O&(BK&�Q�ݯ'��GCv/Bg�D��������N�w%�l$�b13+�5 �'p.8�q@FM�����_��֯�����\#%X�l�Ҳ����ۡ�rlu߼��>I�gT_A���X��|����,^%�g��n1%]%��zU��I3?�P�Fͤ�Ot�1E��E�t4s<\�O���x�	t��(��<���.��FF��@��5as%�9�;�'��5�z���&W���pE��7KJU�R�W�\�,���A&�GG��F<LL[| �߳A�s�pE�OOD��寬�c�\G�
R�;tLq��>��1
�ʃ#t�mtZ1�G�ͧ}�p�/o�5u(�+�ߕTr��G#aup��<�� �����Z"����J' ��&\k��q���O�:�f��·�t)eW6p��h�U *7�O�$�"����oX6kmMm���ѧBf�k>�X&y�j�Gq���*XT���4<��U��m`�3�8{�﶑T� ��F�2y9�9��!ܸ�]�n����\�^�E��ϑ��n)���0���|�gB�C��O��C�^v4�D��uS��891�L o�� Ɂjb������2yg!�(c΢)����%��݋?�%6��(d����y�LP���PǥՑQݹ��4w�Y��*����60�&�$�.��9F<���+�D�fO��d���#Fh����l��i�Q�#�W �t����Ml����N�T��&�m� ��cpE�4��9�eζ�h�&:6�J~��G0�{O���{���#!����3��L<����x�c �
u�U��Q�ں⚻]�]�x߿��ڽ�,P5�J�z����wr��4Ӑm+��L��W�}d����{�x�p(+��򠙜m+;:�T�b-zۂ�`�&,�`�'�*zd�M��2p	/������`���/��g����s�l����,n�(������'1�g�+�Ŭ��UʉXm@q���Ƕ��eHP�c(�j�h�G���q� �:㏡nC���i��2%G�Mȱ���iؒ�� >��^�?R��qm�ԧ�q�-�|Sk�<<�,C����(B����q�������Ģ�9��|w#�<!��و� �|6�6s��9�oQ�Dp�L��\\\\|t����U:̅l+I
Vo�y܎#\j���0�\w5u�o7��#q�@��?���J����?E�(�(��W%�a}�(H�VG�@�A2d��������nt5����z�G �f �@�i���g��8�?��Ak��͍��h2��	�>�)�-@9@ at�����Zm�D�9��M�U�Di!��x��:��E�Q<�Ah�:F�RK�4����TW��&�F�TK�����60��� ��wY;.�Y����3W�4�[�F7�C�.6�����������.%�e��G���Sbp��ƙ8�]}�#�k/w�n���ұ;_�j���f�M�2G�Z�������t�X��	�Ա����/��m)iB�{�4���p�s�U�-�m.�0&&�
���.F;c�a���ߗC�T:g&T��EM��>=�c�ag]mUt�ġ�;�(mME����q����.:t���2�-�I��?�q{�"lԙ=�Μ���򕪱����mgU&������/�tɁ3i����o����c��5���]ȓ�ߎ��k����y��������*���F(FJ�MY;@��[kgH�<w6�:ㅟ�b�o�CnX_�E�e��R�8�9������HyD@e��6��:�D�w5��P�M���}������b�����cw'�V��e0#*�1�����yn#�W�\7�폓0|�rB${@�����e|���ip��������T@U8:b��`�_>	C_rz��X���n��9!�dM��)O���G��q�R�Ixo���g������=nOOu<1���ky�ho��UF:}�]?� X+4��orSs���:�=��'�_�=ʀ��&0�*������h?      D   �   x��1�0k�� ��aC��?�9� #A���$����b�mV���<�V!��m!%�MoЩ����x�S)a�zL)���2���;�E��M)l����l�2�؎�t�M��)
����e�A��t�����.�e��5N��bF���dab%�X�R��@�]pK�m����Q*ҩ�kwB � �M��      H   �   x��Ա1��ڞ�=
�sP2�5!D���� ����O�w����d��t`B����/�A^��� VZc��ݳ��1�^u���T��p0p��H��pJEǱ���7���A@Z�U�I������Z���Ag�,�qs�-3 \��      O   ;   x���42�,OM�6�,.I,�L�/-��OL)��M,I-�L�)����72�+HI����� ��       T   \   x�3�42�t/*-P�H,)N,(Pq��7?#?O!7��4;;1O�8�2Q!;U!,�FF����
V&V�z&�f���\1z\\\ \�4�      J   9  x�mSMo�@=��A*)NJ�S�� !��\&�����k�G��{��	iQ/^��ͼ�7ϭ�5_&v��I�N,�'2EIS�V}OV|��}g~�����1+M1$I�ղ�QMH�u@rҔe� NJI���q�Dv�P����r���� ��#2v���?�����7�C�ܳ$����3^��#�dkK�-f�+��r@����c�5�ƴ�M�]��I0$Βydb����Xr0�Ѵ75�r�&�ٴ����})�ˠ�Z���9�Z��нJ'FT���@�vqk�-��Bb�c��W��zm�x���-tZ�=`G�i��ش�*�G�
���gu!
�{�}I9ŦR�9U����ܴ�Ht�mYU*�l�.j��&�g��9�]�}�+��$�(�\�BpJ!�Ъ���p3�XY\��=���!�]Z��O�ݪ�;��:x�N0�Rn1�#j��`UPݕٸ��6L���j����������_���1�sV�����-]��?�t����x�F'�_)7Vب�j�J.�R�:����yz{Ue��3�Y�](�B�cp߯���i���m�      Q      x������ � �      B   �  x����R�8���)�`����!�B�I2�f#[r��m3�6���s��7c��
J����,�Mb�<�u�}�݆��ڔ�+�JS�:���7W���{]}���ü��f^Zǜ��g�E���Hd�r�sA���`:���+2'9ui�¯���W�4oV�}^�=�B*R01|d�	j��,n��������$�p(|0E0�[�!�JR�dn�1��e��F�LI���<�.0jlF���{L �>3�/�}����~�>]�������ҊG���a���;k��Z��3^��Ҫ\��fό�+:r>zܴ]�u; *!�Q��M��~��i�խ?��?�?_�ɷ�e{�	�
ʃ�ǂ2���(
*�4�Ds�QK�1F;x!.YnA8��{���J������@Rr���q��uE��K���$��2({y����Cl=�T	�:*���Zr��8�e�[*����`��9��D;�<����n�m�N�)y݅*��/�iH"���L�c�I^+wRc�HNN�v��:TuEr��L�c�I^ḕF��+�i|���n]��'Dz�3�='y���;a�W�7�M�[���!�I��z&ڑ�$�2Ȫ�@5=��E���w̯UZ��L�{��ȎYh!�&���׋�j�[�E/ӻ��	z�u�Z	e�S�6�m��ݏ��o=){�>j&�=��ģ�yF��g�E|�\��
^�T�һ��	y�tY�cfّw$��n����u��3�,'a�
[��б/�_W�z$�� �93o�9��0�\���][T�_B�-q����L�#��.���]Cq�b��b����V ��<ʙ��]�˱����Ԃ|��豴mb�mH��� g��w����@l�!ɧeu_������mE��A��D��w:	����+r�a<�%�p�J�G5���t]68`0l%�_`����s�W�3�c��Hj�S���-�)���5i؉�xǞ��k���ג��+��
�N����I]�����w�Bˆl�cÑo+<�,!Jҭ�X0�g"YN�hi�f}`hJ�W�O>ĥ�P��u��3��,_8�9a�c�f��g�|�m�!���t�(gB�w�.�V���Ԝ�����6�yW���v����L��}��p������U���D�X�b{�0�3.��y%��%��e��o\��_�D;���{Hj��P�8T�gO�>��^B�r���=�J3͆�I���\�|��d�N��9�M�����/o��P���/k�����W/�hyN���X�������k��=~�{���tE�{]?vjG���_Ì��x]�ۃ���bl�B�b�9Ȇ�c����_q*Y=�I���	��./Z���9��h�}Ȳ<sL� L"391R�M����<:�΄�����\���ƞ{���l%�⒴������     