PGDMP  8    3                |            coba    16.4    16.4 ;    1           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            2           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            3           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            4           1262    16470    coba    DATABASE     {   CREATE DATABASE coba WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_Indonesia.1252';
    DROP DATABASE coba;
                postgres    false            �            1259    16522    admins    TABLE     3  CREATE TABLE public.admins (
    id integer NOT NULL,
    fullname character varying(255) NOT NULL,
    username character varying(255) NOT NULL,
    password character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.admins;
       public         heap    postgres    false            �            1259    16521    admins_id_seq    SEQUENCE     �   CREATE SEQUENCE public.admins_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.admins_id_seq;
       public          postgres    false    223            5           0    0    admins_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.admins_id_seq OWNED BY public.admins.id;
          public          postgres    false    222            �            1259    16471 
   enrollment    TABLE     `   CREATE TABLE public.enrollment (
    id_kelas integer NOT NULL,
    id_user integer NOT NULL
);
    DROP TABLE public.enrollment;
       public         heap    postgres    false            �            1259    24777    jawaban    TABLE     �   CREATE TABLE public.jawaban (
    id_jawaban integer NOT NULL,
    id_user integer NOT NULL,
    id_soal integer NOT NULL,
    jawaban text NOT NULL
);
    DROP TABLE public.jawaban;
       public         heap    postgres    false            �            1259    24776    jawaban_id_jawaban_seq    SEQUENCE     �   CREATE SEQUENCE public.jawaban_id_jawaban_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.jawaban_id_jawaban_seq;
       public          postgres    false    227            6           0    0    jawaban_id_jawaban_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.jawaban_id_jawaban_seq OWNED BY public.jawaban.id_jawaban;
          public          postgres    false    226            �            1259    16474 
   kelas_ajar    TABLE     �   CREATE TABLE public.kelas_ajar (
    nama_mapel character(255) NOT NULL,
    kelas character(5) NOT NULL,
    id_kelas integer NOT NULL,
    token character(20) NOT NULL
);
    DROP TABLE public.kelas_ajar;
       public         heap    postgres    false            �            1259    16477    kelas_ajar_id_kelas_seq    SEQUENCE     �   CREATE SEQUENCE public.kelas_ajar_id_kelas_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.kelas_ajar_id_kelas_seq;
       public          postgres    false    216            7           0    0    kelas_ajar_id_kelas_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.kelas_ajar_id_kelas_seq OWNED BY public.kelas_ajar.id_kelas;
          public          postgres    false    217            �            1259    16478    kuis    TABLE     �   CREATE TABLE public.kuis (
    id_kuis integer NOT NULL,
    id_kelas integer NOT NULL,
    judul_kuis character(255) NOT NULL
);
    DROP TABLE public.kuis;
       public         heap    postgres    false            �            1259    16481    kuis_id_kuis_seq    SEQUENCE     �   CREATE SEQUENCE public.kuis_id_kuis_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.kuis_id_kuis_seq;
       public          postgres    false    218            8           0    0    kuis_id_kuis_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.kuis_id_kuis_seq OWNED BY public.kuis.id_kuis;
          public          postgres    false    219            �            1259    24763    soal    TABLE     �   CREATE TABLE public.soal (
    id_soal integer NOT NULL,
    id_kuis integer NOT NULL,
    pertanyaan text NOT NULL,
    kunci_jawaban text NOT NULL
);
    DROP TABLE public.soal;
       public         heap    postgres    false            �            1259    24762    soal_id_soal_seq    SEQUENCE     �   CREATE SEQUENCE public.soal_id_soal_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.soal_id_soal_seq;
       public          postgres    false    225            9           0    0    soal_id_soal_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.soal_id_soal_seq OWNED BY public.soal.id_soal;
          public          postgres    false    224            �            1259    16482    users    TABLE     �  CREATE TABLE public.users (
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
       public         heap    postgres    false            �            1259    16489    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    220            :           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    221            q           2604    16525 	   admins id    DEFAULT     f   ALTER TABLE ONLY public.admins ALTER COLUMN id SET DEFAULT nextval('public.admins_id_seq'::regclass);
 8   ALTER TABLE public.admins ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    222    223    223            t           2604    24780    jawaban id_jawaban    DEFAULT     x   ALTER TABLE ONLY public.jawaban ALTER COLUMN id_jawaban SET DEFAULT nextval('public.jawaban_id_jawaban_seq'::regclass);
 A   ALTER TABLE public.jawaban ALTER COLUMN id_jawaban DROP DEFAULT;
       public          postgres    false    227    226    227            m           2604    16536    kelas_ajar id_kelas    DEFAULT     z   ALTER TABLE ONLY public.kelas_ajar ALTER COLUMN id_kelas SET DEFAULT nextval('public.kelas_ajar_id_kelas_seq'::regclass);
 B   ALTER TABLE public.kelas_ajar ALTER COLUMN id_kelas DROP DEFAULT;
       public          postgres    false    217    216            n           2604    16491    kuis id_kuis    DEFAULT     l   ALTER TABLE ONLY public.kuis ALTER COLUMN id_kuis SET DEFAULT nextval('public.kuis_id_kuis_seq'::regclass);
 ;   ALTER TABLE public.kuis ALTER COLUMN id_kuis DROP DEFAULT;
       public          postgres    false    219    218            s           2604    24766    soal id_soal    DEFAULT     l   ALTER TABLE ONLY public.soal ALTER COLUMN id_soal SET DEFAULT nextval('public.soal_id_soal_seq'::regclass);
 ;   ALTER TABLE public.soal ALTER COLUMN id_soal DROP DEFAULT;
       public          postgres    false    224    225    225            o           2604    16492    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    221    220            *          0    16522    admins 
   TABLE DATA           U   COPY public.admins (id, fullname, username, password, email, created_at) FROM stdin;
    public          postgres    false    223   2C       "          0    16471 
   enrollment 
   TABLE DATA           7   COPY public.enrollment (id_kelas, id_user) FROM stdin;
    public          postgres    false    215   �C       .          0    24777    jawaban 
   TABLE DATA           H   COPY public.jawaban (id_jawaban, id_user, id_soal, jawaban) FROM stdin;
    public          postgres    false    227   �C       #          0    16474 
   kelas_ajar 
   TABLE DATA           H   COPY public.kelas_ajar (nama_mapel, kelas, id_kelas, token) FROM stdin;
    public          postgres    false    216   �C       %          0    16478    kuis 
   TABLE DATA           =   COPY public.kuis (id_kuis, id_kelas, judul_kuis) FROM stdin;
    public          postgres    false    218   {D       ,          0    24763    soal 
   TABLE DATA           K   COPY public.soal (id_soal, id_kuis, pertanyaan, kunci_jawaban) FROM stdin;
    public          postgres    false    225   �D       '          0    16482    users 
   TABLE DATA           j   COPY public.users (id, fullname, username, password, email, role, nisn_or_nuptk, is_accepted) FROM stdin;
    public          postgres    false    220   sE       ;           0    0    admins_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.admins_id_seq', 1, true);
          public          postgres    false    222            <           0    0    jawaban_id_jawaban_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('public.jawaban_id_jawaban_seq', 3, true);
          public          postgres    false    226            =           0    0    kelas_ajar_id_kelas_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.kelas_ajar_id_kelas_seq', 12, true);
          public          postgres    false    217            >           0    0    kuis_id_kuis_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.kuis_id_kuis_seq', 6, true);
          public          postgres    false    219            ?           0    0    soal_id_soal_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.soal_id_soal_seq', 2, true);
          public          postgres    false    224            @           0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 17, true);
          public          postgres    false    221            �           2606    16534    admins admins_email_key 
   CONSTRAINT     S   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_email_key UNIQUE (email);
 A   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_email_key;
       public            postgres    false    223            �           2606    16530    admins admins_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_pkey;
       public            postgres    false    223            �           2606    16532    admins admins_username_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_username_key UNIQUE (username);
 D   ALTER TABLE ONLY public.admins DROP CONSTRAINT admins_username_key;
       public            postgres    false    223            x           2606    16494    enrollment enrollment_pkey 
   CONSTRAINT     g   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT enrollment_pkey PRIMARY KEY (id_kelas, id_user);
 D   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT enrollment_pkey;
       public            postgres    false    215    215            �           2606    24784    jawaban jawaban_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_pkey PRIMARY KEY (id_jawaban);
 >   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_pkey;
       public            postgres    false    227            z           2606    16496    kelas_ajar kelas_ajar_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.kelas_ajar
    ADD CONSTRAINT kelas_ajar_pkey PRIMARY KEY (id_kelas);
 D   ALTER TABLE ONLY public.kelas_ajar DROP CONSTRAINT kelas_ajar_pkey;
       public            postgres    false    216            |           2606    16498    kuis kuis_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT kuis_pkey PRIMARY KEY (id_kuis);
 8   ALTER TABLE ONLY public.kuis DROP CONSTRAINT kuis_pkey;
       public            postgres    false    218            �           2606    24770    soal soal_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.soal
    ADD CONSTRAINT soal_pkey PRIMARY KEY (id_soal);
 8   ALTER TABLE ONLY public.soal DROP CONSTRAINT soal_pkey;
       public            postgres    false    225            ~           2606    16500    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    220            �           2606    16502    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    220            �           2606    16504    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public            postgres    false    220            �           2606    16505    enrollment id_kelas    FK CONSTRAINT     �   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas) NOT VALID;
 =   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_kelas;
       public          postgres    false    216    4730    215            �           2606    16510    kuis id_kelas    FK CONSTRAINT     x   ALTER TABLE ONLY public.kuis
    ADD CONSTRAINT id_kelas FOREIGN KEY (id_kelas) REFERENCES public.kelas_ajar(id_kelas);
 7   ALTER TABLE ONLY public.kuis DROP CONSTRAINT id_kelas;
       public          postgres    false    218    4730    216            �           2606    16515    enrollment id_user    FK CONSTRAINT     q   ALTER TABLE ONLY public.enrollment
    ADD CONSTRAINT id_user FOREIGN KEY (id_user) REFERENCES public.users(id);
 <   ALTER TABLE ONLY public.enrollment DROP CONSTRAINT id_user;
       public          postgres    false    220    4736    215            �           2606    24790    jawaban jawaban_id_soal_fkey    FK CONSTRAINT        ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_id_soal_fkey FOREIGN KEY (id_soal) REFERENCES public.soal(id_soal);
 F   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_id_soal_fkey;
       public          postgres    false    4746    225    227            �           2606    24785    jawaban jawaban_id_user_fkey    FK CONSTRAINT     {   ALTER TABLE ONLY public.jawaban
    ADD CONSTRAINT jawaban_id_user_fkey FOREIGN KEY (id_user) REFERENCES public.users(id);
 F   ALTER TABLE ONLY public.jawaban DROP CONSTRAINT jawaban_id_user_fkey;
       public          postgres    false    227    220    4736            �           2606    24771    soal soal_id_kuis_fkey    FK CONSTRAINT     y   ALTER TABLE ONLY public.soal
    ADD CONSTRAINT soal_id_kuis_fkey FOREIGN KEY (id_kuis) REFERENCES public.kuis(id_kuis);
 @   ALTER TABLE ONLY public.soal DROP CONSTRAINT soal_id_kuis_fkey;
       public          postgres    false    225    4732    218            *   E   x�3�LL��̃�ũ9�F��CjEbnAN�^r~.��������������������������1W� ���      "   #   x�34�44�24���\�F`���5����� | �      .   5   x�3�44�4�LO�V(I,UHJ�KW�2��'�1�g�Y��X������ Wk      #   l   x�KN�V���� DZr&ZZ$���!$��GLC�����$9�!˕�X2��(:�I�&��Y��ԬĢČs� X�1�Nj�yR��AB�+F��� �R�x      %      x�3�44�L�OJT��+F��� {�"Q      ,   �   x�U���0D��+��+bc�X�Ĵ��%.��ǅ��X��N�m��1c@O�K���T��$>HG���k���_k��h�\R�J<��l�.D�P�GJATY9�����N�\�E���oPy�@���DyC',xf����uX�$�zt;���^�ϕX<b�ك�{~���l���]6ι7K�ls      '   �  x�u�KO\1F�w~ǬQ�y��By�*hKG�ıs)�Ӣ��U7L#%V���1శ�<���ý������ܴ�q�9�],���p�W�?ͱhl�$��519 ��5e-$9��d���e�iDֿq;�*ߗ[�n�J���<m0<��7"�;�<:��z��}�ݹ����*)U@r���gH#i���5��<�k�D�_��C��za���߷S�Lu�w�������z�p���q��T84�RO�]��pU����ZH�U��c�c�P���H��j���#`ǚ4��n��6��{��K�/�͟�.�]UC�K�q.�J��Lb�������Kb1�4KJ�C��"D*����8�E	�$,�bK3{�����ǽ�W�继�:�[�"�9��9�R��K!O�3;��REt�0So//Yo����E]ٷ��l����     